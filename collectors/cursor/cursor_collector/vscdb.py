"""Passive scanner for Cursor's local SQLite state (state.vscdb).

Best-effort fallback surface: Cursor stores AI-service history in
``ItemTable`` rows (``aiService.generations``, ``aiService.prompts`` in the
global db; ``composer.composerData`` per workspace). The format is
undocumented and version-fragile, so everything here is defensive:
unparseable values are skipped, never fatal.

Access discipline: the live db is copied to a temp file first and opened
read-only, so we never lock or mutate Cursor's database. Content policy:
values are inspected for metadata keys only (model, token counts); any
text content in entries is discarded without being stored or emitted.

Delta emission is resumable via the state-dir checkpoint: per (db, key) we
remember how many list entries were already seen and emit only the tail.
"""

import json
import os
import shutil
import sqlite3
import tempfile
import time
import urllib.parse
from pathlib import Path

from . import events, mcp_inventory, paths, pricing, spool, state

# ItemTable keys we try to read, per db kind.
_GLOBAL_KEYS = ("aiService.generations", "aiService.prompts")
_WORKSPACE_KEYS = ("composer.composerData",)

# Tool-call note (AIM-86): none of these keys reliably expose agent tool
# invocations as structured records. aiService.generations/prompts are
# request/response entries (model, tokens, text); composer.composerData
# holds conversation metadata, while bubble-level tool records (tool name
# + args) live in a separate undocumented, version-fragile surface
# (cursorDiskKV bubble blobs) that we deliberately do not parse — guessing
# at it would risk emitting content-adjacent data. Tool-call telemetry
# therefore comes from the postToolUse hook path (hook.py), where Cursor
# documents tool_name/duration. Unblock condition for this path: Cursor
# publishes/stabilizes the bubble schema or an export API for tool calls.

# List field names observed/guessed inside JSON values (undocumented).
_LIST_FIELDS = ("generations", "prompts", "entries", "items", "conversations")

_SESSION_KEYS = ("conversationId", "conversation_id", "chatId", "sessionId")


def _copy_db(path: Path) -> Path | None:
    """Copy the db to a temp file so we never touch Cursor's live file."""
    try:
        fd, tmp = tempfile.mkstemp(prefix="aim-vscdb-", suffix=".db")
        os.close(fd)
        shutil.copy2(path, tmp)
        return Path(tmp)
    except OSError:
        return None


def _read_key(db: Path, key: str) -> str | None:
    """Read one ItemTable value from a copied db, opened read-only."""
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            row = con.execute(
                "SELECT value FROM ItemTable WHERE key = ?", (key,)).fetchone()
        finally:
            con.close()
    except sqlite3.Error:
        return None
    if not row:
        return None
    v = row[0]
    return v if isinstance(v, str) else None


def _entries(value: str | None) -> list:
    """Parse an ItemTable JSON value into a list of entries; [] on any
    deviation from the expected shape (undocumented format)."""
    if not value:
        return []
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for field in _LIST_FIELDS:
            if isinstance(data.get(field), list):
                return data[field]
    return []


def _entry_session(entry: dict, fallback: str) -> str:
    for k in _SESSION_KEYS:
        v = entry.get(k)
        if isinstance(v, str) and v:
            return v
    return fallback


def _entry_tokens(entry: dict) -> tuple[int | None, int | None]:
    def _int(*keys):
        for k in keys:
            v = entry.get(k)
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0:
                return int(v)
        return None
    usage = entry.get("usage") if isinstance(entry.get("usage"), dict) else {}
    tin = _int("tokensIn", "tokens_in", "inputTokens", "input_tokens") or _int_in(usage, "input_tokens", "prompt_tokens")
    tout = _int("tokensOut", "tokens_out", "outputTokens", "output_tokens") or _int_in(usage, "output_tokens", "completion_tokens")
    return tin, tout


def _int_in(d: dict, *keys) -> int | None:
    for k in keys:
        v = d.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0:
            return int(v)
    return None


def _entry_model(entry: dict) -> str | None:
    for k in ("model", "modelName", "model_name"):
        v = entry.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _workspace_folder(db_path: Path) -> str | None:
    """Best-effort workspace path from the sibling workspace.json."""
    try:
        data = json.loads((db_path.parent / "workspace.json").read_text())
    except (OSError, json.JSONDecodeError):
        return None
    folder = data.get("folder")
    if not isinstance(folder, str):
        return None
    if folder.startswith("file://"):
        parsed = urllib.parse.urlparse(folder)
        folder = urllib.parse.unquote(parsed.path)
        # Windows URIs look like file:///C:/x -> strip the leading slash.
        if len(folder) >= 3 and folder[0] == "/" and folder[2] == ":":
            folder = folder[1:]
    return folder


def _scan_db(db_path: Path, keys: tuple[str, ...], seen: dict,
             cwd: str | None) -> tuple[list[dict], dict]:
    """Emit events for entries past the seen-count of each key."""
    out: list[dict] = []
    tmp = _copy_db(db_path)
    if tmp is None:
        return out, seen
    try:
        for key in keys:
            entries = _entries(_read_key(tmp, key))
            start = int(seen.get(key, 0))
            if start > len(entries):  # value shrank/rotated: resync
                start = 0
            for entry in entries[start:]:
                if not isinstance(entry, dict):
                    continue
                model = _entry_model(entry)
                tokens_in, tokens_out = _entry_tokens(entry)
                try:
                    ev = events.new_event(
                        raw_session_id=_entry_session(
                            entry, fallback=f"{db_path}:{key}"),
                        model=model,
                        cwd=cwd,
                        tokens_in=tokens_in,
                        tokens_out=tokens_out,
                        cost_estimate_usd=pricing.estimate_cost(
                            model, tokens_in, tokens_out),
                    )
                except ValueError:
                    continue  # fail closed on a malformed aggregate
                out.append(ev)
            seen[key] = len(entries)
    finally:
        tmp.unlink(missing_ok=True)
    return out, seen


def scan_once() -> int:
    """One pass over the global and per-workspace state.vscdb files.
    Missing dbs/keys emit nothing and are not an error. Returns the number
    of events emitted."""
    cp = state.load_checkpoint()
    dbs = cp.setdefault("vscdb", {})
    out: list[dict] = []

    targets = [(paths.global_state_db(), _GLOBAL_KEYS, None)]
    workspace_folders: list[str] = []
    for p in paths.workspace_state_dbs():
        folder = _workspace_folder(p)
        if folder:
            workspace_folders.append(folder)
        targets.append((p, _WORKSPACE_KEYS, folder))

    for db_path, keys, cwd in targets:
        if not db_path.is_file():
            continue
        seen = dbs.setdefault(str(db_path), {})
        try:
            evs, seen = _scan_db(db_path, keys, seen, cwd)
        except Exception:
            continue  # version-fragile surface: skip-and-log, never crash
        dbs[str(db_path)] = seen
        out.extend(evs)

    # MCP server config inventory (AIM-97/AIM-570): one event when the
    # configured (name, scope) set changed. Workspace paths come from
    # workspaceStorage (never re-emitted).
    try:
        inv_ev = mcp_inventory.scan(cp, workspaces=workspace_folders)
    except Exception:
        inv_ev = None
    if inv_ev is not None:
        out.append(inv_ev)

    state.save_checkpoint(cp)
    spool.append(out)
    return len(out)


def watch(interval: float = 30.0) -> None:
    """Daemon loop. Runs until killed (Intune/scheduled task manages it)."""
    from . import enroll
    last_hb = 0.0  # first iteration heartbeats immediately (liveness on start)
    while True:
        try:
            scan_once()
            spool.flush()
            last_hb = enroll.maybe_heartbeat(last_hb)
        except Exception:
            pass  # stay alive; a collector must not crash-loop visibly
        time.sleep(interval)
