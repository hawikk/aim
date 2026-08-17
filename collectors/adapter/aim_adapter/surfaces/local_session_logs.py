"""Surface: local session / log files (depth when the tool logs tokens/models).

Formats:
- ``jsonl_usage`` / ``json_session`` — text session / usage logs
- ``sqlite_table`` — metadata columns from a local SQLite state DB
  (e.g. OpenAI Codex CLI ``state_*.sqlite`` threads table). Only columns
  named in ``field_map`` are SELECTed; content columns are hard-denied.
- ``legacy`` — hand-written collector package
"""

from __future__ import annotations

import glob as globmod
import json
import os
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

# Column names that must never be selected from a tool SQLite DB, even if a
# misconfigured field_map asks for them. Codex threads stores prompt-adjacent
# text in several of these; agent job tables hold free-form instruction JSON.
_SQLITE_CONTENT_COLUMNS = frozenset(
    {
        "first_user_message",
        "preview",
        "title",
        "git_origin_url",
        "instruction",
        "row_json",
        "result_json",
        "description",
        "input_schema",
        "output_schema_json",
        "input_headers_json",
        "last_error",
        "agent_nickname",
        "agent_role",
        "successes",
        "failures",
        "rollout_path",
    }
)

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Sibling files next to metadata stores that must never be parsed as sessions
# (Cline keeps API keys in ~/.cline/data/secrets.json beside globalState.json).
_REFUSED_SESSION_FILES = frozenset(
    {
        "secrets.json",
        "secret.json",
        "credentials.json",
        "auth.json",
        # Continue local telemetry / session index: prompt+completion live here.
        "chatinteraction.jsonl",
        "autocomplete.jsonl",
        "editinteraction.jsonl",
        "nexteditwithhistory.jsonl",
        "sessions.json",
        # Tabnine cloud token + config sit next to discovery.
        ".refresh_token_v2",
        "tabnine_config.json",
    }
)

_GLOB_CHARS = frozenset("*?[")


@dataclass
class DiscoveryResult:
    tool_id: str
    present: bool
    in_use: bool
    version: str | None
    surface: str
    evidence: str
    error: str | None = None
    paths: list[str] = field(default_factory=list)


def _expand(path_template: str, root_override: str | None = None) -> Path:
    s = os.path.expandvars(os.path.expanduser(path_template))
    if root_override:
        # For tests: treat ~ as root_override
        if path_template.startswith("~/"):
            s = str(Path(root_override) / path_template[2:])
        elif path_template.startswith("~"):
            s = str(Path(root_override) / path_template[1:].lstrip("/"))
    return Path(s)


def _expand_all(path_template: str, root_override: str | None = None) -> list[Path]:
    """Expand ~ / ${ENV} and optional glob stars. Missing paths yield []."""
    expanded = _expand(path_template, root_override)
    if not any(ch in path_template for ch in _GLOB_CHARS):
        return [expanded] if expanded.exists() else []
    hits = globmod.glob(str(expanded), recursive=True)
    out: list[Path] = []
    seen: set[Path] = set()
    for raw in hits:
        p = Path(raw)
        if not p.exists():
            continue
        try:
            key = p.resolve()
        except OSError:
            key = p
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _matches_session_glob(path: Path, session_glob: str) -> bool:
    name = path.name
    posix = path.as_posix()
    for pattern in (p.strip() for p in str(session_glob).split(",")):
        if not pattern:
            continue
        base = Path(pattern).name
        if fnmatch(name, base) or fnmatch(name, pattern):
            return True
        if fnmatch(posix, pattern) or fnmatch(posix, f"**/{pattern.lstrip('/')}"):
            return True
    return False


def discover(
    manifest: dict[str, Any],
    surface: dict[str, Any],
    *,
    root: str | None = None,
) -> DiscoveryResult:
    tool_id = manifest["id"]
    discovery = surface.get("discovery") or {}
    paths_cfg = list(discovery.get("paths") or [])
    found: list[Path] = []
    for tmpl in paths_cfg:
        found.extend(_expand_all(tmpl, root))
    binaries = list(discovery.get("binaries") or [])
    bin_hit = False
    for b in binaries:
        # PATH probe — presence only
        for d in os.environ.get("PATH", "").split(os.pathsep):
            cand = Path(d) / b
            if cand.is_file() and os.access(cand, os.X_OK):
                bin_hit = True
                break
        if bin_hit:
            break

    present = bool(found) or bin_hit
    in_use = False
    evidence_parts: list[str] = []
    if found:
        evidence_parts.append(f"paths={len(found)}")
        # recent mtime within 7 days ⇒ in_use
        import time

        now = time.time()
        for p in found:
            try:
                if now - p.stat().st_mtime < 7 * 86400:
                    in_use = True
            except OSError:
                pass
            # also check children for session activity
            try:
                for child in p.rglob("*"):
                    if child.is_file():
                        if now - child.stat().st_mtime < 7 * 86400:
                            in_use = True
                            break
            except OSError:
                pass
    if bin_hit:
        evidence_parts.append("binary=1")
        present = True

    return DiscoveryResult(
        tool_id=tool_id,
        present=present,
        in_use=in_use or present and bool(found),
        version=None,
        surface="local_session_logs",
        evidence=",".join(evidence_parts) or "none",
        paths=[str(p) for p in found],
    )


def _map_fields(obj: dict[str, Any], field_map: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for logical, src in field_map.items():
        if src in obj:
            out[logical] = obj[src]
    # pass through already-logical keys
    for k in (
        "model",
        "tokens_in",
        "tokens_out",
        "session_id",
        "ts",
        "provider",
        "cost_estimate_usd",
        "tool_version",
        "repo_key",
    ):
        if k in obj and k not in out:
            out[k] = obj[k]
    return out


def _validate_ident(name: str, kind: str) -> str | None:
    if not name or not _IDENT_RE.fullmatch(name):
        return f"sqlite_table: invalid {kind} identifier {name!r}"
    return None


def _copy_sqlite(path: Path) -> Path | None:
    """Copy live DB to a temp file so we never lock or mutate the tool's DB."""
    try:
        fd, tmp = tempfile.mkstemp(prefix="aim-sqlite-", suffix=".db")
        os.close(fd)
        shutil.copy2(path, tmp)
        return Path(tmp)
    except OSError:
        return None


def _extract_sqlite_table(
    path: Path,
    *,
    table: str,
    field_map: dict[str, str],
) -> tuple[list[dict[str, Any]], int, list[str]]:
    """Read only field_map source columns from ``table``; map to logical keys."""
    failures: list[str] = []
    err = _validate_ident(table, "table")
    if err:
        return [], 0, [err]

    source_cols: list[str] = []
    seen: set[str] = set()
    for src in field_map.values():
        err = _validate_ident(src, "column")
        if err:
            return [], 0, [err]
        if src.lower() in _SQLITE_CONTENT_COLUMNS:
            return [], 0, [f"sqlite_table: refused content column {src!r}"]
        if src not in seen:
            seen.add(src)
            source_cols.append(src)

    if not source_cols:
        return [], 0, ["sqlite_table: field_map empty"]

    tmp = _copy_sqlite(path)
    if tmp is None:
        return [], 0, [f"sqlite_table: copy failed:{path.name}"]

    rows_raw: list[dict[str, Any]] = []
    try:
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        try:
            # Quote identifiers after whitelist validation only.
            col_sql = ", ".join(f'"{c}"' for c in source_cols)
            sql = f'SELECT {col_sql} FROM "{table}"'
            cur = con.execute(sql)
            for tup in cur.fetchall():
                rows_raw.append(dict(zip(source_cols, tup)))
        except sqlite3.Error as e:
            failures.append(f"sqlite_table:query:{type(e).__name__}")
            return [], 0, failures
        finally:
            con.close()
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass

    mapped_rows: list[dict[str, Any]] = []
    dropped = 0
    for obj in rows_raw:
        mapped = _map_fields(obj, field_map)
        # Drop empty / content-only residue
        if not any(k in mapped for k in ("ts", "session_id", "model", "tokens_in")):
            dropped += 1
            continue
        mapped_rows.append(mapped)
    return mapped_rows, dropped, failures


def extract_rows(
    manifest: dict[str, Any],
    surface: dict[str, Any],
    *,
    root: str | None = None,
    records: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], int, list[str]]:
    """Return (rows, dropped, failures).

    If ``records`` is provided (tests / streamed inject), parse those.
    Otherwise scan discovery paths with session_glob.
    """
    extraction = surface.get("extraction") or {}
    field_map = dict(extraction.get("field_map") or {})
    fmt = extraction.get("format") or "jsonl_usage"
    dropped = 0
    failures: list[str] = []
    rows: list[dict[str, Any]] = []

    if fmt == "legacy":
        return [], 0, ["legacy: delegated to hand-written collector package"]

    def handle_obj(obj: dict[str, Any]) -> None:
        nonlocal dropped
        if not isinstance(obj, dict):
            dropped += 1
            return
        mapped = _map_fields(obj, field_map) if field_map else dict(obj)
        # must have some temporal or session signal
        if not any(k in mapped for k in ("ts", "session_id", "model", "tokens_in")):
            dropped += 1
            return
        rows.append(mapped)

    if records is not None:
        for rec in records:
            handle_obj(rec)
        return rows, dropped, failures

    discovery = surface.get("discovery") or {}
    session_glob = extraction.get("session_glob") or (
        "state_*.sqlite" if fmt == "sqlite_table" else "**/*.jsonl"
    )
    sqlite_cfg = extraction.get("sqlite") or {}
    table = sqlite_cfg.get("table") or "threads"
    seen_files: set[Path] = set()

    for tmpl in discovery.get("paths") or []:
        bases = _expand_all(tmpl, root)
        if not bases:
            continue
        matches: list[Path] = []
        seen: set[Path] = set()
        try:
            for base in bases:
                if base.is_dir():
                    for pattern in (p.strip() for p in str(session_glob).split(",")):
                        if not pattern:
                            continue
                        for hit in sorted(base.glob(pattern)):
                            if hit not in seen:
                                seen.add(hit)
                                matches.append(hit)
                elif _matches_session_glob(base, session_glob):
                    if base not in seen:
                        seen.add(base)
                        matches.append(base)
        except OSError as e:
            failures.append(f"glob:{e}")
            continue
        for path in matches:
            if not path.is_file():
                continue
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen_files:
                continue
            seen_files.add(resolved)

            if fmt == "sqlite_table":
                # Skip SQLite sidecar files if a broad glob ever matches them.
                name = path.name
                if name.endswith(("-wal", "-shm", "-journal")):
                    continue
                if not field_map:
                    failures.append("sqlite_table: field_map required")
                    continue
                got, d, fails = _extract_sqlite_table(
                    path, table=table, field_map=field_map
                )
                rows.extend(got)
                dropped += d
                failures.extend(fails)
                continue

            if path.name.lower() in _REFUSED_SESSION_FILES:
                failures.append(f"json_session: refused secrets file:{path.name}")
                continue

            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                failures.append(f"read:{path.name}:{e}")
                continue
            if fmt == "jsonl_usage":
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        handle_obj(json.loads(line))
                    except json.JSONDecodeError:
                        dropped += 1
            elif fmt == "json_session":
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    dropped += 1
                    continue
                records_key = extraction.get("records_key")
                items: list[dict[str, Any]] = []
                if isinstance(data, list):
                    items = [item for item in data if isinstance(item, dict)]
                elif isinstance(data, dict):
                    key = None
                    if isinstance(records_key, str) and records_key:
                        err = _validate_ident(records_key, "records_key")
                        if err:
                            failures.append(err)
                            continue
                        key = records_key
                    elif isinstance(data.get("events"), list):
                        key = "events"
                    if key is not None:
                        raw_list = data.get(key)
                        if isinstance(raw_list, list):
                            items = [item for item in raw_list if isinstance(item, dict)]
                        else:
                            dropped += 1
                            continue
                    else:
                        items = [data]
                else:
                    dropped += 1
                    continue
                for item in items:
                    handle_obj(item)
            else:
                failures.append(f"unsupported format {fmt}")
    return rows, dropped, failures
