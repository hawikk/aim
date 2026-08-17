"""Kilo CLI (standalone) session scan from the local SQLite DB.

The VS Code extension and the standalone ``kilo`` CLI are two product
surfaces of the same sanctioned tool family. Extension tasks live under
VS Code ``globalStorage`` (see ``tasks.py``). The CLI stores sessions in
``~/.local/share/kilo/kilo.db`` (XDG data home) with token/cost columns
on the ``session`` table — there is no hook API.

Metadata only:

- Read ``session`` token/cost/model/version/directory columns.
- Locally scan ``message`` / ``part`` text for secret/PII matchers, then
  discard content. Flags only leave the endpoint.
- Never emit directory paths, prompts, or message bodies.
- Copy the live DB to a temp file before opening read-only so the CLI is
  never locked or mutated (same posture as Cursor ``state.vscdb``).
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from . import events, matchers, paths

# Checkpoint key under the shared kilo checkpoint file.
_CP_KEY = "cli_sessions"


def _copy_db_readonly(db_path: Path) -> Path | None:
    """Copy kilo.db (+ wal/shm if present) to a temp dir; return copy path."""
    if not db_path.is_file():
        return None
    tmpdir = Path(tempfile.mkdtemp(prefix="aim-kilo-cli-"))
    dest = tmpdir / "kilo.db"
    try:
        shutil.copy2(db_path, dest)
        for suffix in ("-wal", "-shm"):
            side = Path(str(db_path) + suffix)
            if side.is_file():
                shutil.copy2(side, Path(str(dest) + suffix))
    except OSError:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None
    return dest


def _cleanup_db_copy(copied: Path | None) -> None:
    if copied is None:
        return
    try:
        shutil.rmtree(copied.parent, ignore_errors=True)
    except OSError:
        pass


def _parse_model(raw: str | None) -> str | None:
    """session.model is often JSON ``{"id": "...", "providerID": "..."}``."""
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s:
        return None
    if s.startswith("{"):
        try:
            data = json.loads(s)
        except json.JSONDecodeError:
            return s[:128]
        if isinstance(data, dict):
            for key in ("id", "modelID", "modelId", "model"):
                v = data.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()[:128]
        return None
    return s[:128]


def _tool_version(session_version: str | None) -> str:
    """Surface-tagged version so CLI vs IDE is distinguishable in events."""
    ver = (session_version or "").strip() or paths.cli_version() or "unknown"
    # Cap so full string fits schema tool_version maxLength 64: "cli/" + ver
    return ("cli/" + ver)[:64]


def _token_totals(row: dict[str, Any]) -> tuple[int, int, float | None]:
    """Fold cache-read into tokens_in (schema v1, same as IDE path)."""
    tin = int(row.get("tokens_input") or 0)
    tin += int(row.get("tokens_cache_read") or 0)
    tout = int(row.get("tokens_output") or 0)
    cost = row.get("cost")
    cost_f = float(cost) if cost is not None else None
    return tin, tout, cost_f


def _scan_session_flags(conn: sqlite3.Connection, session_id: str) -> list:
    """Local content scan only — flags leave, text never does."""
    flags: list = []
    try:
        msgs = conn.execute(
            "SELECT data FROM message WHERE session_id = ? LIMIT 200",
            (session_id,),
        ).fetchall()
        parts = conn.execute(
            "SELECT data FROM part WHERE session_id = ? LIMIT 400",
            (session_id,),
        ).fetchall()
    except sqlite3.Error:
        return []
    for (blob,) in list(msgs) + list(parts):
        if not isinstance(blob, str) or not blob:
            continue
        # Prefer scanning only text-like fields if JSON; fall back to raw.
        text = blob
        if blob.startswith("{"):
            try:
                data = json.loads(blob)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict):
                chunks = []
                for k in ("text", "content", "prompt", "summary"):
                    v = data.get(k)
                    if isinstance(v, str):
                        chunks.append(v)
                    elif isinstance(v, dict):
                        # summary.diffs etc. — stringify keys only is useless;
                        # skip nested structures to avoid accidental content
                        # expansion beyond what we need for detectors.
                        pass
                text = "\n".join(chunks) if chunks else ""
        if text:
            flags.extend(matchers.scan_text_matches(text))
    return flags


def _load_sessions(db_path: Path) -> list[dict[str, Any]]:
    copied = _copy_db_readonly(db_path)
    if copied is None:
        return []
    rows: list[dict[str, Any]] = []
    try:
        conn = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(
                """
                SELECT id, directory, version, model, cost,
                       tokens_input, tokens_output, tokens_reasoning,
                       tokens_cache_read, tokens_cache_write,
                       time_created, time_updated
                FROM session
                """
            )
            for r in cur.fetchall():
                rows.append(dict(r))
            for row in rows:
                sid = row.get("id")
                if isinstance(sid, str) and sid:
                    row["_flags"] = _scan_session_flags(conn, sid)
                else:
                    row["_flags"] = []
        except sqlite3.Error:
            rows = []
        finally:
            conn.close()
    finally:
        _cleanup_db_copy(copied)
    return rows


def collect(cp: dict) -> list[dict]:
    """Delta-emit usage events from all discoverable Kilo CLI databases.

    Checkpoint shape under ``cli_sessions``::

        {
          "<db_path>::<session_id>": {
            "time_updated": int,
            "tokens_input": int,
            "tokens_output": int,
            "tokens_cache_read": int,
            "cost": float,
            "emitted": bool,
          }
        }

    A session emits:

    1. On first sight when it has any activity signal (model, tokens, cost,
       or local match flags) — absolute totals for that snapshot.
    2. On later updates when token totals or cost increase — delta only.

    Zero-token sessions with only a model still emit once so the CLI surface
    is visible in pilot (presence proof).
    """
    store: dict = cp.setdefault(_CP_KEY, {})
    out: list[dict] = []
    for db_path in paths.cli_db_paths():
        for row in _load_sessions(db_path):
            sid = row.get("id")
            if not isinstance(sid, str) or not sid:
                continue
            key = f"{db_path}::{sid}"
            prev = store.get(key) or {}
            tin, tout, cost = _token_totals(row)
            time_updated = int(row.get("time_updated") or 0)
            model = _parse_model(row.get("model") if isinstance(row.get("model"), str) else None)
            flags = row.get("_flags") or []
            has_signal = bool(model) or tin > 0 or tout > 0 or (cost or 0) > 0 or bool(flags)

            prev_tin = int(prev.get("tokens_in") or 0)
            prev_tout = int(prev.get("tokens_out") or 0)
            prev_cost = float(prev.get("cost") or 0.0)
            first = not prev.get("emitted")

            if first:
                if not has_signal:
                    # Remember sighting so we do not re-poll empty shells forever
                    # without blocking a later real update.
                    store[key] = {
                        "time_updated": time_updated,
                        "tokens_in": tin,
                        "tokens_out": tout,
                        "cost": cost if cost is not None else 0.0,
                        "emitted": False,
                    }
                    continue
                emit_in, emit_out = (tin or None), (tout if tout else None)
                emit_cost = cost
            else:
                d_in = max(0, tin - prev_tin)
                d_out = max(0, tout - prev_tout)
                d_cost = None
                if cost is not None:
                    d_cost = max(0.0, float(cost) - prev_cost)
                if d_in == 0 and d_out == 0 and not (d_cost and d_cost > 0):
                    # Still advance checkpoint timestamps.
                    store[key] = {
                        "time_updated": time_updated,
                        "tokens_in": tin,
                        "tokens_out": tout,
                        "cost": cost if cost is not None else prev_cost,
                        "emitted": True,
                    }
                    continue
                emit_in = d_in or None
                emit_out = d_out or None
                emit_cost = d_cost if d_cost and d_cost > 0 else None

            ts = row.get("time_updated") or row.get("time_created")
            directory = row.get("directory") if isinstance(row.get("directory"), str) else None
            # Skip filesystem root placeholders that are not real workspaces.
            if directory in ("/", ""):
                directory = None
            try:
                ev = events.new_event(
                    session_id=events.daily_session_id(sid, ts),
                    model=model,
                    ts_epoch_ms=ts,
                    workspace_path=directory,
                    tokens_in=int(emit_in) if emit_in is not None else None,
                    tokens_out=int(emit_out) if emit_out is not None else None,
                    cost_usd=float(emit_cost) if emit_cost is not None else None,
                    flags=flags,
                    tool_version=_tool_version(
                        row.get("version") if isinstance(row.get("version"), str) else None
                    ),
                )
            except (ValueError, TypeError):
                continue
            out.append(ev)
            store[key] = {
                "time_updated": time_updated,
                "tokens_in": tin,
                "tokens_out": tout,
                "cost": cost if cost is not None else 0.0,
                "emitted": True,
            }
    return out
