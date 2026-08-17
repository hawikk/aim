"""Metadata-only extraction from local GitHub Copilot surfaces (AIM-1167).

Honesty contract
----------------
GitHub does **not** persist suggestion-accept / token counters on the
endpoint in a documented, stable form. This extractor therefore emits
only what is actually on disk:

* tool identity + extension / plugin / CLI version
* selected model, when a settings or session *metadata* key names one
* per-session hash (filename / sessionId) and last-write timestamp
* chat/agent/inline turn *counts* (``len(requests)``) — never the turns

Content keys (prompt, completion, chat text, file paths, tokens of
code) are never copied onto a record. A fixture that plants leak
markers in those keys must not appear in any emitted event.

Auth / secret files (``hosts.json``, ``token.json``, …) are never opened.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import paths

_MAX_FILE_BYTES = 8 * 1024 * 1024

# Keys that must never be read as values and whose objects are not walked.
_CONTENT_KEYS = frozenset(
    {
        "prompt",
        "prompt_text",
        "message",
        "messages",
        "content",
        "text",
        "response",
        "response_text",
        "body",
        "input",
        "output",
        "completion",
        "completions",
        "chat",
        "value",
        "markdown",
        "parts",
        "file",
        "files",
        "path",
        "uri",
        "url",
        "code",
        "source",
        "arguments",
        "args",
        "command",
        "cmdline",
        "variabledata",
        "variables",
        "references",
        "copilot_references",
        "attachments",
    }
)

_MODEL_KEYS = frozenset(
    {
        "model",
        "modelid",
        "modelname",
        "model_id",
        "model_name",
        "selectedmodel",
        "selectedcompletionmodel",
        "languagemodel",
        "engine",
        "overrideengine",
        "copilot_model",
    }
)

_SESSION_ID_KEYS = frozenset(
    {
        "sessionid",
        "session_id",
        "conversationid",
        "conversation_id",
        "id",
    }
)

_TS_KEYS = frozenset(
    {
        "creationdate",
        "lastmessagedate",
        "updatedat",
        "createdat",
        "timestamp",
        "ts",
    }
)

_SETTINGS_MODEL_KEYS = (
    "github.copilot.selectedCompletionModel",
    "github.copilot.chat.defaultLanguageModel",
    "github.copilot.chat.model",
    "github.copilot.advanced.debug.overrideEngine",
)

_VSCDB_MODEL_KEYS = (
    "github.copilot.selectedCompletionModel",
    "github.copilot.chat.defaultLanguageModel",
    "github.copilot.installVersion",
)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_MODEL_SAFE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:+-]{0,127}$")


@dataclass(frozen=True)
class SessionRecord:
    """One metadata-only Copilot observation. No content fields."""

    raw_session_id: str
    ts_epoch_s: float
    model: str | None
    tool_version: str | None
    surface: str
    kind: str  # chat | inline | agent | inventory
    request_count: int
    source_key: str
    mtime: float
    size: int


def _stat(path: Path) -> tuple[float, int]:
    try:
        st = path.stat()
        return float(st.st_mtime), int(st.st_size)
    except OSError:
        return 0.0, 0


def _read_json(path: Path) -> Any | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return _loads_jsonc(text)


def _loads_jsonc(text: str) -> Any | None:
    """Best-effort JSONC (VS Code settings allow comments / trailing commas)."""
    no_block = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    lines = []
    for line in no_block.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        lines.append(re.sub(r"\s+//.*$", "", line))
    cleaned = re.sub(r",\s*([}\]])", r"\1", "\n".join(lines))
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def _norm_key(k: str) -> str:
    return k.replace("-", "").replace("_", "").lower()


def _safe_model(value: Any) -> str | None:
    if isinstance(value, dict):
        for k in ("id", "name", "family", "model"):
            got = _safe_model(value.get(k))
            if got:
                return got
        return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or len(s) > 128:
        return None
    if not _MODEL_SAFE_RE.fullmatch(s):
        return None
    return s


def _as_epoch_s(raw: Any) -> float | None:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    n = float(raw)
    if n <= 0:
        return None
    if n > 10_000_000_000:  # ms
        n = n / 1000.0
    return n


def _model_from_request(req: dict) -> str | None:
    """Allowlisted metadata only — never message/response/content."""
    got = _safe_model(req.get("model") or req.get("modelId") or req.get("modelName"))
    if got:
        return got
    result = req.get("result")
    if isinstance(result, dict):
        meta = result.get("metadata")
        if isinstance(meta, dict):
            for k, v in meta.items():
                if _norm_key(k) in _MODEL_KEYS:
                    got = _safe_model(v)
                    if got:
                        return got
        got = _safe_model(result.get("model") or result.get("modelId"))
        if got:
            return got
    return None


def _session_meta(data: dict) -> dict[str, Any]:
    model = None
    raw_id = None
    ts = None
    kind = "chat"
    request_count = 0

    for k, v in data.items():
        nk = _norm_key(str(k))
        if nk in _CONTENT_KEYS:
            continue
        if nk in _SESSION_ID_KEYS and isinstance(v, str) and _UUID_RE.fullmatch(v):
            raw_id = v
        if nk in _TS_KEYS:
            parsed = _as_epoch_s(v)
            if parsed is not None:
                ts = parsed
        if nk in _MODEL_KEYS:
            got = _safe_model(v)
            if got:
                model = got
        if nk == "initiallocation" and isinstance(v, str):
            loc = v.lower()
            if loc in ("editor", "inline"):
                kind = "inline"
            elif "agent" in loc:
                kind = "agent"
        if nk in ("agent", "isagent") and v is True:
            kind = "agent"
        if nk == "mode" and isinstance(v, str) and "agent" in v.lower():
            kind = "agent"

    requests = data.get("requests")
    if isinstance(requests, list):
        request_count = len(requests)
        for req in requests:
            if not isinstance(req, dict):
                continue
            got = _model_from_request(req)
            if got:
                model = got
    return {
        "model": model,
        "raw_id": raw_id,
        "ts": ts,
        "kind": kind,
        "request_count": request_count,
    }


def _settings_model() -> str | None:
    for path in paths.settings_files():
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        for key in _SETTINGS_MODEL_KEYS:
            got = _safe_model(data.get(key))
            if got:
                return got
        advanced = data.get("github.copilot.advanced")
        if isinstance(advanced, dict):
            got = _safe_model(advanced.get("debug.overrideEngine"))
            if got:
                return got
    return None


def _copy_sqlite(path: Path) -> Path | None:
    try:
        fd, tmp = tempfile.mkstemp(prefix="aim-copilot-vscdb-", suffix=".db")
        os.close(fd)
        shutil.copy2(path, tmp)
        return Path(tmp)
    except OSError:
        return None


def _vscdb_metadata() -> dict[str, str]:
    """Allowlisted ItemTable keys only. Values must look like model/version."""
    out: dict[str, str] = {}
    for db in paths.vscode_state_dbs():
        tmp = _copy_sqlite(db)
        if tmp is None:
            continue
        try:
            con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
            try:
                for key in _VSCDB_MODEL_KEYS:
                    try:
                        row = con.execute(
                            "SELECT value FROM ItemTable WHERE key = ?", (key,)
                        ).fetchone()
                    except sqlite3.Error:
                        continue
                    if not row or not isinstance(row[0], str):
                        continue
                    raw = row[0].strip()
                    if raw.startswith("{") or raw.startswith("["):
                        try:
                            parsed = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        got = _safe_model(parsed)
                    else:
                        got = _safe_model(raw)
                    if got:
                        out[key] = got
            finally:
                con.close()
        except sqlite3.Error:
            pass
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
    return out


def _plugin_xml_version(plugin_dir: Path) -> str | None:
    for rel in (Path("META-INF") / "plugin.xml", Path("plugin.xml")):
        xml_path = plugin_dir / rel
        if not xml_path.is_file():
            continue
        try:
            if xml_path.stat().st_size > _MAX_FILE_BYTES:
                continue
            root = ET.parse(xml_path).getroot()
        except (OSError, ET.ParseError):
            continue
        ver = root.findtext("version")
        if ver and ver.strip():
            return ver.strip()[:64]
        # idea-plugin attributes
        attr = root.attrib.get("version")
        if attr:
            return attr.strip()[:64]
    return None


def _jetbrains_option_model(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None
    for opt in root.iter("option"):
        name = (opt.attrib.get("name") or "").lower()
        if "model" not in name and "engine" not in name:
            continue
        val = opt.attrib.get("value")
        got = _safe_model(val)
        if got:
            return got
    return None


def _tool_version_for(surface: str, *, chat: bool = False) -> str | None:
    if surface.startswith("jetbrains"):
        for d in paths.jetbrains_plugin_dirs():
            ver = _plugin_xml_version(d)
            if ver:
                return f"jetbrains/{ver}"[:64]
        return None
    if surface.startswith("cli"):
        # CLI rarely writes a version file; report presence only.
        return "cli"
    ver = paths.extension_version(chat=chat)
    if not ver:
        return None
    prefix = "chat" if chat else "vscode"
    return f"{prefix}/{ver}"[:64]


def _record_from_session_file(
    path: Path,
    *,
    fallback_model: str | None,
    tool_version: str | None,
    surface: str,
) -> SessionRecord | None:
    data = _read_json(path)
    mtime, size = _stat(path)
    if not isinstance(data, dict):
        # Unreadable / non-object: still a session file — emit id + mtime only.
        stem = path.stem
        raw_id = stem if _UUID_RE.fullmatch(stem) else f"file:{stem}"[:80]
        return SessionRecord(
            raw_session_id=raw_id,
            ts_epoch_s=mtime or 0.0,
            model=fallback_model,
            tool_version=tool_version,
            surface=surface,
            kind="chat",
            request_count=0,
            source_key=str(path),
            mtime=mtime,
            size=size,
        )
    meta = _session_meta(data)
    stem = path.stem
    raw_id = meta["raw_id"]
    if not raw_id:
        raw_id = stem if _UUID_RE.fullmatch(stem) else f"file:{stem}"[:80]
    ts = meta["ts"] if meta["ts"] is not None else mtime
    return SessionRecord(
        raw_session_id=str(raw_id),
        ts_epoch_s=float(ts or 0.0),
        model=meta["model"] or fallback_model,
        tool_version=tool_version,
        surface=surface,
        kind=meta["kind"],
        request_count=int(meta["request_count"] or 0),
        source_key=str(path),
        mtime=mtime,
        size=size,
    )


def _inventory_record(
    *,
    raw_id: str,
    ts: float,
    model: str | None,
    tool_version: str | None,
    surface: str,
    source_key: str,
    mtime: float,
    size: int,
) -> SessionRecord:
    return SessionRecord(
        raw_session_id=raw_id,
        ts_epoch_s=ts,
        model=model,
        tool_version=tool_version,
        surface=surface,
        kind="inventory",
        request_count=0,
        source_key=source_key,
        mtime=mtime,
        size=size,
    )


def collect_records() -> list[SessionRecord]:
    """Walk every local Copilot surface and return metadata-only records."""
    settings_model = _settings_model()
    vscdb = _vscdb_metadata()
    if not settings_model:
        for key in (
            "github.copilot.selectedCompletionModel",
            "github.copilot.chat.defaultLanguageModel",
        ):
            if key in vscdb:
                settings_model = vscdb[key]
                break

    vscode_ver = _tool_version_for("vscode", chat=False)
    chat_ver = _tool_version_for("vscode", chat=True)
    records: list[SessionRecord] = []
    seen_keys: set[str] = set()

    for path in paths.chat_session_files():
        rec = _record_from_session_file(
            path,
            fallback_model=settings_model,
            tool_version=chat_ver or vscode_ver,
            surface="vscode_chat",
        )
        if rec is None or rec.source_key in seen_keys:
            continue
        seen_keys.add(rec.source_key)
        records.append(rec)

    for path in paths.cli_session_candidates():
        rec = _record_from_session_file(
            path,
            fallback_model=settings_model,
            tool_version=_tool_version_for("cli"),
            surface="cli",
        )
        if rec is None or rec.source_key in seen_keys:
            continue
        seen_keys.add(rec.source_key)
        records.append(rec)

    # JetBrains: plugin presence + optional model in options XML
    jb_model = settings_model
    jb_mtime = 0.0
    jb_size = 0
    for opt in paths.jetbrains_option_files():
        got = _jetbrains_option_model(opt)
        if got:
            jb_model = got
        mt, sz = _stat(opt)
        jb_mtime = max(jb_mtime, mt)
        jb_size = max(jb_size, sz)
    jb_dirs = paths.jetbrains_plugin_dirs()
    if jb_dirs:
        ver = _tool_version_for("jetbrains")
        for d in jb_dirs:
            mt, sz = _stat(d)
            jb_mtime = max(jb_mtime, mt)
            jb_size = max(jb_size, sz)
        records.append(
            _inventory_record(
                raw_id="inventory:github_copilot:jetbrains",
                ts=jb_mtime or 0.0,
                model=jb_model,
                tool_version=ver,
                surface="jetbrains",
                source_key="inventory:jetbrains",
                mtime=jb_mtime,
                size=jb_size,
            )
        )

    # VS Code extension installed but no session files: one inventory event
    exts = paths.discover_extensions()
    storages = paths.storage_dirs()
    if exts or storages:
        last_m = 0.0
        last_s = 0
        for hit in exts:
            mt, sz = _stat(hit["path"])
            last_m = max(last_m, mt)
            last_s = max(last_s, sz)
        for st in storages:
            mt, sz = _stat(st)
            last_m = max(last_m, mt)
            last_s = max(last_s, sz)
        records.append(
            _inventory_record(
                raw_id="inventory:github_copilot:vscode",
                ts=last_m or 0.0,
                model=settings_model,
                tool_version=chat_ver or vscode_ver,
                surface="vscode",
                source_key="inventory:vscode",
                mtime=last_m,
                size=last_s,
            )
        )

    if paths.cli_present() and not any(r.surface == "cli" and r.kind != "inventory" for r in records):
        homes = paths.cli_homes()
        mt = sz = 0.0
        for h in homes:
            m, s = _stat(h)
            mt = max(mt, m)
            sz = max(sz, s)
        records.append(
            _inventory_record(
                raw_id="inventory:github_copilot:cli",
                ts=float(mt),
                model=settings_model,
                tool_version=_tool_version_for("cli"),
                surface="cli",
                source_key="inventory:cli",
                mtime=float(mt),
                size=int(sz),
            )
        )

    return records


def discover() -> dict[str, Any]:
    """Network-free discovery summary (tests + ``aim`` detect)."""
    exts = paths.discover_extensions()
    return {
        "present": paths.any_surface_present(),
        "extensions": [
            {"id": e["id"], "version": e.get("version")} for e in exts
        ],
        "storage_dirs": len(paths.storage_dirs()),
        "chat_sessions": len(paths.chat_session_files()),
        "jetbrains_plugins": len(paths.jetbrains_plugin_dirs()),
        "cli": paths.cli_present(),
    }
