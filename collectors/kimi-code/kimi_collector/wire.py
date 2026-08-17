"""Parsing of Kimi Code wire.jsonl logs into schema v1 events.

On-disk layout per session agent:

    sessions/<wd_dir>/session_<uuid>/agents/<agent>/wire.jsonl
        JSONL protocol wire log. First line is
        ``{"type": "metadata", "protocol_version": ..., "created_at": ...}``;
        later lines are protocol records. Telemetry lives in:

        - ``llm.request``   — one per LLM API call. Safe fields used here:
          ``time`` (epoch ms), ``model``, ``modelAlias``, ``provider``,
          ``turnStep``, ``kind``; the rest (``systemPromptHash``,
          ``toolsHash``, ...) is ignored. Retried calls repeat the record
          with an extra ``attempt`` field.
        - ``usage.record``  — token accounting per call, in the same order
          as the requests it settles: ``usage`` =
          ``{inputOther, inputCacheRead, inputCacheCreation, output}``,
          plus ``model`` (the alias), ``time``, ``usageScope`` ("turn").

        Other record types (``context.append_message``,
        ``context.append_loop_event``, ...) carry full prompt/response
        text. They are parsed only far enough to skip them — with one
        exception: ``context.append_loop_event`` records nesting a
        ``tool.call`` event are counted by tool NAME only (AIM-97,
        mirroring the Claude Code collector's AIM-86). ``args``,
        ``description``, ``display`` and every ``tool.result`` payload are
        never read.

Content policy: message content never leaves the endpoint. ``turn.prompt``
text is scanned locally by the endpoint matchers (same ruleset as the other
collectors) and then discarded; only detector names go on the event via
``match_flags`` (AIM-88). All other content-bearing records are never read
beyond their ``type`` field.

Emission unit: one event per ``usage.record`` (≈ one per completed LLM API
call), paired positionally with the most recent ``llm.request`` for
model/provider/turnStep. Incremental: the checkpoint stores a byte offset
per wire file, so each scan emits only newly appended records. Tool calls
are aggregated per wire file keyed by (tool_name, mcp_server) and
delta-emitted as one ``event_type="tool_use"`` event per scan when new
calls appear — independently of usage records (AIM-97).

Unsettled requests / quota-ended turns: a turn can end without its last
``llm.request`` ever producing a ``usage.record`` — e.g. Kimi's turn ends
because the account ran out of quota, so the final call never settles.
Positional pairing must not carry that dangling request forward onto the
NEXT turn's first ``usage.record`` (it would attach the wrong
model/provider/turnStep/time). A ``pending`` request therefore lives only
within its turn: a new ``turn.prompt`` (turn boundary) clears any
still-unsettled request. Cross-scan survival WITHIN a turn is preserved (a
request and its usage may straddle two scan passes).
"""

from __future__ import annotations

import json
from pathlib import Path

from . import events, matchers

WIRE_NAME = "wire.jsonl"

_MAX_CHUNK_BYTES = 64 * 1024 * 1024

# Coarse action classification (schema v1.1 enum). Any MCP tool is mcp_call;
# anything not listed here is "other" — never a guess. Built-in names from
# the tool registry observed in real wire logs (Bash, Read, Edit, Write,
# Glob, Grep, WebSearch, FetchURL, Agent, Task*, TodoList, Skill, ...).
_ACTION_CLASS = {
    "Read": "fs_read", "Glob": "fs_read", "Grep": "fs_read",
    "ReadMediaFile": "fs_read",
    "Write": "fs_write", "Edit": "fs_write",
    "Bash": "shell",
    "WebSearch": "network", "FetchURL": "network",
}

# Built-in tools that spawn sub-agents / Task loops (AIM-627 A2A handoffs).
_HANDOFF_TOOL_KIND = {
    "Agent": "subagent",
    "AgentSwarm": "subagent",
    "Task": "task",
    "TaskCreate": "task",
    "TaskOutput": "task",
    "TaskStop": "task",
}


def _split_tool_name(name: str) -> tuple[str, str | None]:
    """Split an MCP tool name (``mcp__<server>__<tool>``) into
    (tool_name, mcp_server), capped to schema lengths. Built-in tools
    return (name, None). Same convention as the other collectors; no MCP
    tool has been observed in real Kimi wire data yet, so malformed
    qualified names fall back to built-in."""
    if name.startswith("mcp__"):
        parts = name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return parts[2][:64], parts[1][:128]
    return name[:64], None


def _prompt_text(rec: dict) -> str | None:
    """Extract prompt text from a turn.prompt record for local scanning.

    Observed shapes: ``input`` is either a plain string or a list of parts
    (``{"type": "text", "text": ...}``). Anything else yields no text.
    The returned text is scanned by the matchers and discarded; it is never
    stored in the checkpoint or emitted.
    """
    inp = rec.get("input")
    if isinstance(inp, str):
        return inp
    if isinstance(inp, list):
        parts = [
            p["text"] for p in inp
            if isinstance(p, dict) and isinstance(p.get("text"), str)
        ]
        if parts:
            return "\n".join(parts)
    return None


def _usage_tokens(usage: dict) -> tuple[int | None, int | None]:
    """Map wire usage counts to schema tokens.

    tokens_in = inputOther + inputCacheRead + inputCacheCreation — all
    input-side counts fold into tokens_in per v1 (same rule as the Kilo
    collector folding cacheReads into input). tokens_out = output.
    """
    if not isinstance(usage, dict):
        return None, None
    def _int(k: str) -> int:
        v = usage.get(k)
        return int(v) if isinstance(v, (int, float)) else 0
    tokens_in = _int("inputOther") + _int("inputCacheRead") + _int("inputCacheCreation")
    out = usage.get("output")
    tokens_out = int(out) if isinstance(out, (int, float)) else None
    return tokens_in, tokens_out


def collect_wire(
    wire_path: Path,
    file_state: dict,
    raw_session_id: str,
    work_dir: str | None,
    tool_version: str | None,
) -> tuple[list[dict], dict]:
    """Emit delta events for one wire.jsonl file.

    ``file_state`` is the persisted checkpoint fragment for this file:
    ``{"offset": n, "pending": {...}|None, "turn_flags": [...],
    "tool_calls": {...}, "emitted_tool_calls": {...}, "model": str|None}``
    where ``pending`` is the safe field subset of the last unpaired
    llm.request, ``turn_flags`` is the current turn's matcher flag entries
    (detector metadata + redacted fingerprints, never content), and ``tool_calls`` /
    ``emitted_tool_calls`` are the per-(tool, MCP server) aggregate and its
    emitted watermark (counts only; AIM-97). Returns (events,
    new_file_state). Never raises.
    """
    state_out = dict(file_state or {})
    offset = int(state_out.get("offset") or 0)
    pending = state_out.get("pending") if isinstance(state_out.get("pending"), dict) else None
    tf = state_out.get("turn_flags")
    # Legacy checkpoints hold bare detector-name strings; current ones hold
    # match_flags entry dicts (names + redacted fingerprints, AIM-225).
    turn_flags = [f for f in tf if isinstance(f, (str, dict))] if isinstance(tf, list) else []
    # checkpoints written before AIM-97 lack the tool-call keys
    tool_calls = state_out.setdefault("tool_calls", {})
    emitted_calls = state_out.setdefault("emitted_tool_calls", {})
    # AIM-799 chain state: discrete invocations keyed by framework toolCallId
    inv = state_out.setdefault("invocations", [])
    seen_ids = state_out.setdefault("seen_tool_call_ids", [])
    if isinstance(seen_ids, list):
        seen_id_set = set(seen_ids)
    else:
        seen_id_set = set()
        seen_ids = []
    id_index = state_out.setdefault("invocation_by_id", {})
    handoffs = state_out.setdefault("handoffs", [])
    open_parents = state_out.setdefault("open_parent_call_ids", [])
    next_seq = int(state_out.get("next_seq") or 0)
    last_model = state_out.get("model") if isinstance(state_out.get("model"), str) else None
    tool_ts: int | float | None = None  # latest tool.call record time
    out: list[dict] = []

    try:
        size = wire_path.stat().st_size
        if size < offset:
            # truncated/rotated: rescan
            offset, pending, turn_flags = 0, None, []
            tool_calls.clear()
            emitted_calls.clear()
            inv.clear()
            seen_id_set.clear()
            seen_ids.clear()
            id_index.clear()
            handoffs.clear()
            open_parents.clear()
            next_seq = 0
            state_out["emitted_invocation_count"] = 0
            state_out["emitted_handoff_count"] = 0
            last_model = None
        if size > offset + _MAX_CHUNK_BYTES:
            return [], state_out  # implausibly large jump; skip rather than load
        with wire_path.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
    except OSError:
        return [], state_out

    # Only consume newline-terminated lines; a trailing partial line (the
    # writer may be mid-append) is left for the next pass.
    lines = chunk.split(b"\n")
    consumed = len(chunk)
    if chunk and not chunk.endswith(b"\n"):
        consumed -= len(lines[-1])
        lines = lines[:-1]

    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        rtype = rec.get("type")
        if rtype == "turn.prompt":
            # New turn boundary: drop any request left unsettled by the
            # previous turn (e.g. a quota-ended turn) so it can never
            # mis-pair forward onto this turn's usage records.
            pending = None
            # Scan this turn's prompt text locally; the text is fingerprinted
            # and discarded here and never leaves the endpoint — only detector
            # metadata (names + redacted fingerprints, AIM-225) is attached to
            # the turn's usage.record events.
            turn_flags = matchers.scan_text_matches(_prompt_text(rec))
        elif rtype == "llm.request":
            pending = {
                "model": rec.get("model"),
                "modelAlias": rec.get("modelAlias"),
                "provider": rec.get("provider"),
                "turnStep": rec.get("turnStep"),
                "time": rec.get("time"),
            }
            m = pending.get("modelAlias") or pending.get("model")
            if isinstance(m, str) and m:
                last_model = m
        elif rtype == "context.append_loop_event":
            # Tool-call counting (AIM-97) + chain fields (AIM-799):
            # read ONLY nested event name + toolCallId + tool.result isError.
            # ``args``/``description``/``display``/result bodies never touched.
            ev_rec = rec.get("event")
            if not isinstance(ev_rec, dict):
                continue
            etype = ev_rec.get("type")
            rt = rec.get("time")
            if isinstance(rt, (int, float)):
                tool_ts = rt
            if etype == "tool.result":
                # Pair result_status only — never result body.
                tid = ev_rec.get("toolCallId")
                if not isinstance(tid, str) or tid not in id_index:
                    continue
                idx = id_index[tid]
                if not (0 <= idx < len(inv)):
                    continue
                result = ev_rec.get("result")
                is_err = None
                if isinstance(result, dict):
                    is_err = result.get("isError")
                if is_err is None:
                    is_err = ev_rec.get("isError")
                inv[idx]["result_status"] = (
                    "error" if is_err is True
                    else "ok" if is_err is False
                    else "unknown"
                )
                cid = inv[idx].get("call_id")
                for h in handoffs:
                    if h.get("_tool_call_id") == tid and h.get("status") == "started":
                        h["status"] = (
                            "failed" if is_err is True else "completed"
                        )
                if cid and open_parents and open_parents[-1] == cid:
                    open_parents.pop()
                continue
            if etype != "tool.call":
                continue
            name = ev_rec.get("name")
            if not isinstance(name, str) or not name:
                continue
            tool, server = _split_tool_name(name)
            entry = tool_calls.setdefault(f"{server or ''}|{tool}", {
                "tool_name": tool,
                "mcp_server": server,
                "action_class": "mcp_call" if server else _ACTION_CLASS.get(tool, "other"),
                "count": 0,
            })
            entry["count"] += 1
            raw_call = ev_rec.get("toolCallId")
            if not isinstance(raw_call, str) or not raw_call or raw_call in seen_id_set:
                continue
            seen_id_set.add(raw_call)
            seen_ids.append(raw_call)
            call_id = events.opaque_call_id(raw_call, tool_ts)
            handoff_kind = _HANDOFF_TOOL_KIND.get(tool) or _HANDOFF_TOOL_KIND.get(name)
            parent = None if handoff_kind else (open_parents[-1] if open_parents else None)
            inv_entry = {
                "tool_name": tool,
                "mcp_server": server,
                "action_class": "mcp_call" if server else _ACTION_CLASS.get(tool, "other"),
                "count": 1,
                "duration_ms": None,
                "call_id": call_id,
                "parent_call_id": parent,
                "result_status": "unknown",
                "seq": next_seq,
                "_tool_call_id": raw_call,
            }
            id_index[raw_call] = len(inv)
            inv.append(inv_entry)
            next_seq += 1
            if handoff_kind:
                handoffs.append({
                    "handoff_kind": handoff_kind,
                    "status": "started",
                    "child_session_id": None,
                    "tool_name": tool[:64],
                    "parent_call_id": call_id,
                    "_tool_call_id": raw_call,
                })
                open_parents.append(call_id)
        elif rtype == "usage.record":
            ts = rec.get("time") if isinstance(rec.get("time"), (int, float)) else None
            tokens_in, tokens_out = _usage_tokens(rec.get("usage"))
            model = None
            provider = None
            if pending:
                model = pending.get("modelAlias") or pending.get("model")
                provider = pending.get("provider")
                if ts is None and isinstance(pending.get("time"), (int, float)):
                    ts = pending["time"]
            if not model:
                model = rec.get("model")
            try:
                ev = events.new_event(
                    session_id=events.daily_session_id(raw_session_id, ts),
                    model=model if isinstance(model, str) else None,
                    ts_epoch_ms=ts,
                    workspace_path=work_dir,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    provider=provider if isinstance(provider, str) else None,
                    flags=turn_flags,
                    tool_version=tool_version,
                )
            except (ValueError, TypeError):
                break  # do not advance past an event we could not build
            out.append(ev)
            pending = None

    # Tool-call deltas (AIM-97 / AIM-799), emitted independently of usage
    # records: a tool_use event goes out even when no usage.record settled
    # this pass. Prefer discrete chain rows when toolCallId was present.
    delta_calls = []
    delta_handoffs = []
    emitted_inv = int(state_out.get("emitted_invocation_count") or 0)
    if len(inv) > emitted_inv:
        for entry in inv[emitted_inv:]:
            delta_calls.append({
                "tool_name": entry["tool_name"],
                "mcp_server": entry["mcp_server"],
                "action_class": entry["action_class"],
                "count": 1,
                "duration_ms": entry.get("duration_ms"),
                "call_id": entry["call_id"],
                "parent_call_id": entry.get("parent_call_id"),
                "result_status": entry.get("result_status") or "unknown",
                "seq": entry.get("seq", 0),
            })
        emitted_h = int(state_out.get("emitted_handoff_count") or 0)
        for h in handoffs[emitted_h:]:
            delta_handoffs.append({
                "handoff_kind": h["handoff_kind"],
                "status": h["status"],
                "child_session_id": h.get("child_session_id"),
                "tool_name": h.get("tool_name"),
                "parent_call_id": h.get("parent_call_id"),
            })
            h["_emitted_status"] = h["status"]
        for h in handoffs[:emitted_h]:
            prev = h.get("_emitted_status")
            if prev != h.get("status") and h.get("status") in (
                    "completed", "failed", "cancelled"):
                delta_handoffs.append({
                    "handoff_kind": h["handoff_kind"],
                    "status": h["status"],
                    "child_session_id": h.get("child_session_id"),
                    "tool_name": h.get("tool_name"),
                    "parent_call_id": h.get("parent_call_id"),
                })
                h["_emitted_status"] = h["status"]
    else:
        for key, entry in tool_calls.items():
            n = entry["count"] - emitted_calls.get(key, 0)
            if n > 0:
                delta_calls.append({
                    "tool_name": entry["tool_name"],
                    "mcp_server": entry["mcp_server"],
                    "action_class": entry["action_class"],
                    "count": n,
                    "duration_ms": None,
                })
        delta_calls.sort(key=lambda d: (d["mcp_server"] or "", d["tool_name"]))

    if delta_calls:
        try:
            ev = events.new_tool_use_event(
                session_id=events.daily_session_id(raw_session_id, tool_ts),
                model=last_model,
                ts_epoch_ms=tool_ts,
                workspace_path=work_dir,
                tool_calls=delta_calls,
                tool_version=tool_version,
                agent_handoffs=delta_handoffs or None,
            )
        except (ValueError, TypeError):
            pass  # do not advance the watermark for an event we could not build
        else:
            out.append(ev)
            for key, entry in tool_calls.items():
                emitted_calls[key] = entry["count"]
            if len(inv) > emitted_inv:
                state_out["emitted_invocation_count"] = len(inv)
                state_out["emitted_handoff_count"] = len(handoffs)

    state_out["offset"] = offset + consumed
    state_out["pending"] = pending
    state_out["turn_flags"] = events.make_flags(turn_flags)
    state_out["model"] = last_model
    state_out["seen_tool_call_ids"] = list(seen_id_set)
    state_out["next_seq"] = next_seq
    state_out["open_parent_call_ids"] = open_parents
    return out, state_out
