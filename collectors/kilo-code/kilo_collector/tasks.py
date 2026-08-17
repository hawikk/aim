"""Parsing of Kilo Code per-task logs into schema v1 events.

On-disk layout per task (Roo Code/Cline lineage):

    tasks/<taskId>/ui_messages.json
        JSON array of UI messages. Token/cost telemetry lives in entries
        with ``type == "say"`` and ``say == "api_req_started"``; their
        ``text`` field is a JSON string carrying ``tokensIn``, ``tokensOut``,
        ``cacheReads``, ``cacheWrites``, ``cost``, ``apiProtocol`` and the
        ``request`` prompt text. Entries are updated in place when a request
        finishes, so an entry without any token/cost field is in-flight and
        must be revisited on the next pass.
    tasks/<taskId>/api_conversation_history.json
        API messages incl. an ``<environment_details>`` block with the
        workspace path. Content-bearing: read locally only, never emitted.

Tool-call capture (pattern): tool activity shows up in
ui_messages.json as ``say == "tool"`` entries whose ``text`` JSON names
the tool in a ``tool`` field (Roo Code/Cline lineage names: ``readFile``,
``writeToFile``, ``executeCommand``, ``browserAction``, ``useMcpTool``,
...), and MCP activity as ``ask == "use_mcp_server"`` /
``say == "mcp_server_request_started"`` / ``say ==
"mcp_server_response"`` entries whose ``text`` JSON names the server and
tool. Only the name fields are read -- the same payloads carry file paths,
command lines and file contents, which are never touched. Calls are
aggregated per task keyed ``"{mcp_server}|{tool_name}"`` and delta-emitted
as ``event_type="tool_use"`` events against the checkpoint fragment.
ui_messages.json is the source of truth; ``tool_use`` blocks in
api_conversation_history.json are NOT read (would double-count).

Content policy: the ``request`` prompt text is scanned by the local
matchers for secret/PII flags and then discarded; only detector metadata
(names + redacted fingerprints) goes on the event. The workspace
path is HMAC-pseudonymized before it leaves this module's caller.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import events, matchers

UI_MESSAGES = "ui_messages.json"
API_HISTORY = "api_conversation_history.json"

_MAX_FILE_BYTES = 64 * 1024 * 1024
_ENV_DETAILS_BYTES = 64 * 1024  # env details are in the first message

_TOKEN_KEYS = ("tokensIn", "tokensOut", "cacheReads", "cacheWrites", "cost")
_MODEL_KEYS = ("model", "modelId", "apiModelId")

# Cline/Roo env details: "# Current Working Directory (/home/u/proj) Files"
# or a bare "# Current Workspace Directory\n/home/u/proj" variant.
_WORKSPACE_RE = re.compile(
    r"#\s*Current (?:Workspace|Working) Directory(?:\s*\(([^)\n]+)\)|[:\s]*\n([^\n]+))"
)


def _read_json(path: Path):
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _parse_text_json(entry: dict) -> dict:
    """Parse a ui_messages entry's ``text`` field (a JSON string) into a
    dict, or {} when absent/unparseable."""
    text = entry.get("text")
    if isinstance(text, str) and text.strip():
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return {}


def _api_req_entries(ui_messages) -> list[tuple[int, dict, dict]]:
    """(seq index, ui entry, parsed text payload) for api_req_started entries."""
    out = []
    if not isinstance(ui_messages, list):
        return out
    seq = 0
    for entry in ui_messages:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "say" or entry.get("say") != "api_req_started":
            continue
        out.append((seq, entry, _parse_text_json(entry)))
        seq += 1
    return out


def _is_complete(payload: dict) -> bool:
    """A request entry is done when any token/cost field is present."""
    return any(payload.get(k) is not None for k in _TOKEN_KEYS)


def _payload_model(payload: dict) -> str | None:
    for k in _MODEL_KEYS:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


# Coarse action classification (schema v1.1+ enum) for the Kilo Code
# (Roo Code/Cline lineage) tool vocabulary. Any MCP tool is mcp_call;
# unknown names fall back to "other", never a guess.
_ACTION_CLASS = {
    "readFile": "fs_read", "searchFiles": "fs_read", "listFiles": "fs_read",
    "listFilesTopLevel": "fs_read", "listFilesRecursive": "fs_read",
    "listCodeDefinitionNames": "fs_read", "codebaseSearch": "fs_read",
    "editedExistingFile": "fs_write", "writeToFile": "fs_write",
    "applyDiff": "fs_write", "insertContent": "fs_write",
    "searchAndReplace": "fs_write",
    "executeCommand": "shell",
    "browserAction": "network",
    "useMcpTool": "mcp_call", "accessMcpResource": "mcp_call",
}

# MCP request-side entries (response-side entries are the second half of
# the request pair and are never counted -- see _extract_tool_calls).
_MCP_SAY = ("mcp_server_request_started",)
_MCP_ASK = ("use_mcp_server",)
_SERVER_KEYS = ("serverName", "server_name", "server")
_TOOL_KEYS = ("toolName", "tool_name", "tool")


def _first_str(payload: dict, keys) -> str | None:
    for k in keys:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _extract_tool_calls(ui_messages, calls: dict) -> int | float | None:
    """Fold tool/MCP activity entries from ui_messages into the per-task
    aggregate ``calls``. Returns the max entry ts seen.

    Only name fields are read: the ``tool`` field of ``say == "tool"``
    payloads, and the server/tool name fields of MCP request payloads. The
    same payloads carry file paths, command lines, URLs and file contents
    -- those keys are never touched.

    Counting rule (to avoid double-counting): one invocation per
    ``say == "tool"`` entry, and per MCP request-side entry
    (``ask == "use_mcp_server"`` or ``say == "mcp_server_request_started"``)
    that yields a tool name. ``say == "mcp_server_response"`` entries are
    the second half of the request pair and are not counted.
    """
    last_ts = None
    if not isinstance(ui_messages, list):
        return last_ts
    for entry in ui_messages:
        if not isinstance(entry, dict):
            continue
        ets = entry.get("ts")
        if isinstance(ets, (int, float)) and (last_ts is None or ets > last_ts):
            last_ts = ets
        etype = entry.get("type")
        tool = server = None
        if etype == "say" and entry.get("say") == "tool":
            payload = _parse_text_json(entry)
            tool = _first_str(payload, ("tool",))
            if tool in ("useMcpTool", "accessMcpResource"):
                server = _first_str(payload, _SERVER_KEYS)
        elif (etype == "say" and entry.get("say") in _MCP_SAY) or (
                etype == "ask" and entry.get("ask") in _MCP_ASK):
            payload = _parse_text_json(entry)
            server = _first_str(payload, _SERVER_KEYS)
            # fall back to the payload's own kind ("use_mcp_tool" /
            # "access_mcp_resource") when no explicit tool name is present
            tool = _first_str(payload, _TOOL_KEYS) or _first_str(payload, ("type",))
        else:
            continue
        if not tool:
            continue  # cannot form a valid tool_calls entry without a name
        tool = tool[:64]
        server = server[:128] if server else None
        key = f"{server or ''}|{tool}"
        agg = calls.setdefault(key, {
            "tool_name": tool,
            "mcp_server": server,
            "action_class": "mcp_call" if server else _ACTION_CLASS.get(tool, "other"),
            "count": 0,
        })
        agg["count"] += 1
    return last_ts


def _history_model_and_workspace(task_dir: Path) -> tuple[str | None, str | None]:
    """Best-effort model + workspace from api_conversation_history.json.

    Reads at most the head of the file. Model is only present in some
    Kilo/Roo versions; workspace comes from the environment_details block.
    """
    path = task_dir / API_HISTORY
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:_ENV_DETAILS_BYTES]
    except OSError:
        return None, None
    workspace = None
    m = _WORKSPACE_RE.search(head)
    if m:
        workspace = (m.group(1) or m.group(2) or "").strip() or None
    model = None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        data = None
    if isinstance(data, list):
        for msg in data:
            if isinstance(msg, dict):
                v = msg.get("model")
                if isinstance(v, str) and v.strip():
                    model = v.strip()
                    break
    return model, workspace


def collect_task(task_dir: Path, task_state: dict, tool_version: str | None) -> tuple[list[dict], dict]:
    """Emit delta events for one task dir.

    ``task_state`` is the persisted checkpoint fragment for this task:
    ``{"processed": n, "model": str, "workspace": str, "history_checked": bool,
    "tool_calls": {key: agg}, "emitted_tool_calls": {key: n}}``.
    Returns (events, new_task_state). Never raises.
    """
    state_out = dict(task_state or {})
    processed = int(state_out.get("processed") or 0)
    ui_messages = _read_json(task_dir / UI_MESSAGES)
    if ui_messages is None:
        return [], state_out

    entries = _api_req_entries(ui_messages)
    out: list[dict] = []
    history_model: str | None = None
    history_workspace: str | None = None
    history_checked = bool(state_out.get("history_checked"))

    for seq, entry, payload in entries:
        if seq < processed:
            continue
        if not _is_complete(payload):
            break  # in-flight; requests complete in order, revisit next pass

        model = _payload_model(payload) or state_out.get("model")
        workspace = state_out.get("workspace")
        if (model is None or workspace is None) and not history_checked:
            history_model, history_workspace = _history_model_and_workspace(task_dir)
            history_checked = True
            state_out["history_checked"] = True
        if model is None:
            model = history_model
        if workspace is None:
            workspace = history_workspace

        ts = entry.get("ts") if isinstance(entry.get("ts"), (int, float)) else None
        tokens_in = payload.get("tokensIn") or 0
        tokens_in += payload.get("cacheReads") or 0  # cache-read folds into input (v1)
        tokens_out = payload.get("tokensOut")
        cost = payload.get("cost")

        try:
            ev = events.new_event(
                session_id=events.daily_session_id(task_dir.name, ts),
                model=model,
                ts_epoch_ms=ts,
                workspace_path=workspace,
                tokens_in=int(tokens_in) if tokens_in else None,
                tokens_out=int(tokens_out) if tokens_out is not None else None,
                cost_usd=float(cost) if cost is not None else None,
                flags=matchers.scan_text_matches(payload.get("request")),
                tool_version=tool_version,
            )
        except (ValueError, TypeError):
            break  # do not advance past an event we could not build
        out.append(ev)
        processed = seq + 1
        if model:
            state_out["model"] = model
        if workspace:
            state_out["workspace"] = workspace

    state_out["processed"] = processed

    # Tool-call deltas, emitted independently of the request
    # cursor: a tool_use event goes out even when no request completed or
    # a request is still in-flight. ui_messages.json is re-read in full
    # every pass, so the aggregate is rebuilt fresh each time and diffed
    # against the emitted counts (incrementing a persisted aggregate
    # would double-count on every pass).
    tool_calls: dict = {}
    emitted_calls = state_out.setdefault("emitted_tool_calls", {})
    last_ts = _extract_tool_calls(ui_messages, tool_calls)
    state_out["tool_calls"] = tool_calls  # latest snapshot, for observability
    delta_calls = []
    # progressive chain fields on aggregates. Aggregate collectors
    # lack discrete tool-call ids; mint an opaque call_id from task + key +
    # end watermark so each delta window is addressable in session chains.
    # result_status is "unknown" — ui_messages lack clean result pairing.
    for key, entry in tool_calls.items():
        prev = emitted_calls.get(key, 0)
        n = entry["count"] - prev
        if n > 0:
            end = entry["count"]
            raw_id = f"{task_dir.name}|{key}|{end}"
            delta_calls.append({
                "tool_name": entry["tool_name"],
                "mcp_server": entry["mcp_server"],
                "action_class": entry["action_class"],
                "count": n,
                # Wall time would need say/ask pairing across incremental
                # scans (pending-call state in the checkpoint); not cleanly
                # derivable, so null (schema-valid) for now.
                "duration_ms": None,
                "call_id": events.opaque_call_id(raw_id),
                "result_status": "unknown",
                "seq": None,  # filled after sort
            })
    if delta_calls:
        delta_calls.sort(key=lambda d: (d["mcp_server"] or "", d["tool_name"]))
        handoffs = []
        for i, d in enumerate(delta_calls):
            d["seq"] = i
            kind = events.handoff_kind_for(d["tool_name"])
            if kind:
                handoffs.append({
                    "handoff_kind": kind,
                    "status": "completed",  # aggregate has no fail signal
                    "tool_name": d["tool_name"][:64],
                    "parent_call_id": d["call_id"],
                    "child_session_id": None,
                })
        try:
            ev = events.new_tool_use_event(
                session_id=events.daily_session_id(task_dir.name, last_ts),
                model=state_out.get("model"),
                ts_epoch_ms=last_ts,
                workspace_path=state_out.get("workspace"),
                tool_calls=delta_calls,
                tool_version=tool_version,
                agent_handoffs=handoffs or None,
            )
        except (ValueError, TypeError):
            pass  # retry next pass; do not mark the delta as emitted
        else:
            out.append(ev)
            for key, entry in tool_calls.items():
                emitted_calls[key] = entry["count"]
    return out, state_out
