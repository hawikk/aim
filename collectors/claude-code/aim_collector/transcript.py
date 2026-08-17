"""Transcript watcher: emit per-session `usage` events from Claude Code
transcripts (~/.claude/projects/**/*.jsonl).

Assistant transcript lines carry message.model and message.usage with token
counts — this is where tokens/cost come from (hook payloads don't have
them). We aggregate per session and emit one `usage` event per flush cycle
per dirty session. Content is never read into events; only numeric usage
fields and tool names are extracted. Personal mode (AIM-77) additionally
runs the local secret/PII matchers over message content IN MEMORY at scan
time (``scan_content=True``): matched content is fingerprinted and discarded
immediately and only detector metadata (name + redacted fingerprint, AIM-225)
lands on the event's match_flags — the metadata-only contract is unchanged.

Tool-call capture (AIM-86 / AIM-627): tool_use blocks in assistant lines
are counted per session keyed by (tool_name, mcp_server), and also tracked
as discrete invocations when a tool_use ``id`` is present (schema v1.10
chain fields: call_id, parent_call_id, result_status, seq). tool_result
blocks contribute only ``is_error`` → result_status (never content).
Task/Agent tools emit agent_handoffs[] metadata. Only names/ids/status
enums are read — never ``input`` or tool result bodies.
"""

import json
import os
import time
from pathlib import Path

from . import events, matchers, mcp_inventory, spool, state

PROJECTS_DIR = "~/.claude/projects"


def _transcript_files() -> list[Path]:
    root = Path(os.environ.get("AIM_CLAUDE_PROJECTS_DIR", PROJECTS_DIR)).expanduser()
    if not root.is_dir():
        return []
    return sorted(root.glob("**/*.jsonl"))


def _read_new_lines(path: Path, offset: int) -> tuple[list[str], int]:
    size = path.stat().st_size
    if size < offset:  # truncated/rotated
        offset = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        fh.seek(offset)
        data = fh.read()
        return data.splitlines(), fh.tell()


def _extract_usage(lines: list[str], agg: dict) -> None:
    """Fold transcript lines into a session aggregate. Metadata only."""
    for line in lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else rec
        if not agg.get("cwd") and isinstance(rec.get("cwd"), str):
            agg["cwd"] = rec["cwd"]
        # Track latest transcript activity time so personal mode can date the
        # event by when usage actually happened (network path ignores this).
        rts = rec.get("timestamp")
        if isinstance(rts, str) and rts > (agg.get("last_ts") or ""):
            agg["last_ts"] = rts
        if rec.get("type") == "assistant" or msg.get("role") == "assistant":
            model = msg.get("model") or agg.get("model")
            if model == "<synthetic>":  # placeholder lines, not real traffic
                model = None
            if model:
                agg["model"] = model
            usage = msg.get("usage") or {}
            agg["tokens"]["input"] += usage.get("input_tokens", 0) or 0
            agg["tokens"]["output"] += usage.get("output_tokens", 0) or 0
            agg["tokens"]["cache_read"] += usage.get("cache_read_input_tokens", 0) or 0
            agg["tokens"]["cache_write"] += usage.get("cache_creation_input_tokens", 0) or 0


# Coarse action classification (schema v1.1 enum). Any MCP tool is mcp_call.
_ACTION_CLASS = {
    "Read": "fs_read", "Glob": "fs_read", "Grep": "fs_read",
    "LS": "fs_read", "NotebookRead": "fs_read",
    "Write": "fs_write", "Edit": "fs_write", "MultiEdit": "fs_write",
    "NotebookEdit": "fs_write",
    "Bash": "shell", "BashOutput": "shell", "KillShell": "shell",
    "WebFetch": "network", "WebSearch": "network",
}


def _split_tool_name(name: str) -> tuple[str, str | None]:
    """Split an MCP tool name (``mcp__<server>__<tool>``) into
    (tool_name, mcp_server), capped to schema lengths. Built-in tools
    return (name, None)."""
    if name.startswith("mcp__"):
        parts = name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return parts[2][:64], parts[1][:128]
    return name[:64], None


# Built-in tools that spawn sub-agents / Task loops (AIM-627 A2A handoffs).
_HANDOFF_TOOL_KIND = {
    "Task": "task",
    "Agent": "subagent",
    "TaskCreate": "task",
    "TaskTool": "task",
}


def _opaque_call_id(tool_use_id: str) -> str:
    """Daily-stable opaque id from the framework tool_use id. Never the raw
    id on the wire — same salt family as session_id (schema day re-hash)."""
    from datetime import datetime, timezone
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # events._hmac64 is internal; use events.session_id domain-separated.
    return events.session_id(f"call|{tool_use_id}", day=day)[:32]


def _extract_tool_calls(lines: list[str], agg: dict) -> None:
    """Fold tool_use blocks into aggregates + discrete chain invocations.

    AIM-86: only the block ``name`` is read for aggregates.
    AIM-627: when ``id`` is present, also record a discrete invocation with
    opaque call_id / seq / parent_call_id; tool_result contributes only
    ``is_error`` → result_status (never content). Task/Agent names append
    agent_handoffs metadata.
    """
    calls = agg["tool_calls"]
    inv = agg.setdefault("invocations", [])  # ordered discrete calls
    seen_ids = agg.setdefault("seen_tool_use_ids", set())
    # checkpoint may reload sets as lists
    if isinstance(seen_ids, list):
        seen_ids = set(seen_ids)
        agg["seen_tool_use_ids"] = seen_ids
    id_index = agg.setdefault("invocation_by_id", {})  # tool_use_id -> inv index
    handoffs = agg.setdefault("handoffs", [])
    open_parents = agg.setdefault("open_parent_call_ids", [])  # stack of Task call_ids
    seq = agg.setdefault("next_seq", 0)

    for line in lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else rec
        content = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(content, list):
            continue

        # tool_result status pairing (user role) — is_error only, never body.
        role = rec.get("type") or msg.get("role")
        if role in ("user",) or msg.get("role") == "user":
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                tid = block.get("tool_use_id")
                if not isinstance(tid, str) or tid not in id_index:
                    continue
                idx = id_index[tid]
                if 0 <= idx < len(inv):
                    is_err = block.get("is_error")
                    inv[idx]["result_status"] = (
                        "error" if is_err is True else "ok" if is_err is False else "unknown"
                    )
                    # Close handoff if this was a Task/Agent tool.
                    cid = inv[idx].get("call_id")
                    for h in handoffs:
                        if h.get("_tool_use_id") == tid and h.get("status") == "started":
                            h["status"] = "failed" if is_err is True else "completed"
                    if cid and open_parents and open_parents[-1] == cid:
                        open_parents.pop()
            continue

        if rec.get("type") != "assistant" and msg.get("role") != "assistant":
            continue

        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            name = block.get("name")
            if not isinstance(name, str) or not name:
                continue
            tool, server = _split_tool_name(name)
            key = f"{server or ''}|{tool}"
            entry = calls.setdefault(key, {
                "tool_name": tool,
                "mcp_server": server,
                "action_class": "mcp_call" if server else _ACTION_CLASS.get(tool, "other"),
                "count": 0,
            })
            entry["count"] += 1

            tool_use_id = block.get("id")
            if not isinstance(tool_use_id, str) or not tool_use_id:
                continue
            if tool_use_id in seen_ids:
                continue
            seen_ids.add(tool_use_id)
            call_id = _opaque_call_id(tool_use_id)
            parent = open_parents[-1] if open_parents else None
            # Task/Agent is top-level handoff — not nested under itself.
            handoff_kind = _HANDOFF_TOOL_KIND.get(tool) or _HANDOFF_TOOL_KIND.get(name)
            if handoff_kind:
                parent = None
            inv_entry = {
                "tool_name": tool,
                "mcp_server": server,
                "action_class": "mcp_call" if server else _ACTION_CLASS.get(tool, "other"),
                "count": 1,
                "duration_ms": None,
                "call_id": call_id,
                "parent_call_id": parent,
                "result_status": "unknown",
                "seq": seq,
                "_tool_use_id": tool_use_id,
                "_agg_key": key,
            }
            id_index[tool_use_id] = len(inv)
            inv.append(inv_entry)
            seq += 1
            agg["next_seq"] = seq
            if handoff_kind:
                handoffs.append({
                    "handoff_kind": handoff_kind,
                    "status": "started",
                    "child_session_id": None,
                    "tool_name": tool[:64],
                    "parent_call_id": call_id,
                    "_tool_use_id": tool_use_id,
                })
                open_parents.append(call_id)


def _flag_key(flag) -> str:
    """Dedupe key for a stored flag entry. Legacy checkpoint entries are bare
    detector names; fingerprinted entries key on detector + fingerprint so a
    NEW secret under an already-seen detector is still emitted (AIM-225)."""
    if isinstance(flag, str):
        return flag
    fp = flag.get("fingerprint")
    return flag["detector"] if not fp else f"{flag['detector']}|{fp}"


def _extract_flags(lines: list[str]) -> list[dict]:
    """Run the local matchers over message content, in memory only.

    Only the ``message`` payload is scanned (not envelope metadata like
    timestamps); matched text is fingerprinted and discarded in-process —
    raw content never reaches the aggregate, the checkpoint, or an event
    (AIM-225). Returns match_flags entries (dicts, JSON-safe so the
    checkpoint can persist them). Used by personal mode only (AIM-77).
    """
    matches = []
    for line in lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = rec.get("message")
        matches += matchers.scan_obj_matches(msg if isinstance(msg, dict) else rec)
    return events.make_flags(matches)


def scan_once(sink=None, checkpoint: str = "checkpoint", ts_from_transcript: bool = False,
              scan_content: bool = False) -> int:
    """One pass over all transcripts. Returns number of events emitted.

    `sink` is a callable taking a list of events; it defaults to the network
    spool. Personal mode (AIM-67) passes a SQLite-backed sink and its own
    `checkpoint` namespace so the two paths never share offset state, and sets
    `ts_from_transcript` so events are dated by real activity time. Personal
    mode also sets `scan_content` (AIM-77) so match_flags are real: content
    is scanned in memory and discarded, only detector names are emitted.
    """
    if sink is None:
        sink = spool.append
    cp = state.load_checkpoint(checkpoint)
    offsets = cp.setdefault("offsets", {})
    aggs = cp.setdefault("sessions", {})
    emitted = 0
    out = []

    for path in _transcript_files():
        key = str(path)
        try:
            lines, new_offset = _read_new_lines(path, offsets.get(key, 0))
        except OSError:
            continue
        offsets[key] = new_offset
        if not lines:
            continue
        session_id = path.stem
        agg = aggs.setdefault(session_id, {
            "model": None, "cwd": None,
            "tokens": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0},
            "emitted_tokens": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0},
            "tool_calls": {}, "emitted_tool_calls": {},
        })
        # checkpoints written before AIM-86 lack the tool-call keys
        tool_calls = agg.setdefault("tool_calls", {})
        emitted_calls = agg.setdefault("emitted_tool_calls", {})
        _extract_usage(lines, agg)
        _extract_tool_calls(lines, agg)
        new_flags: list[dict] = []
        if scan_content:
            seen = {}
            for f in agg.setdefault("flags", []):
                seen[_flag_key(f)] = f
            for entry in _extract_flags(lines):
                seen.setdefault(_flag_key(entry), entry)
            agg["flags"] = [seen[k] for k in sorted(seen)]
            emitted_flags = set(agg.setdefault("emitted_flags", []))
            new_flags = [seen[k] for k in sorted(seen) if k not in emitted_flags]

        # Emit only the delta since last emission, so dashboards can sum.
        # Schema v1 has only tokens_in/tokens_out: cache_read is prompt-side
        # volume, folded into tokens_in (gap noted on AIM-18 for v1.1).
        delta = {k: agg["tokens"][k] - agg["emitted_tokens"][k] for k in agg["tokens"]}
        if any(v > 0 for v in delta.values()) or new_flags:
            ev = events.new_event(
                raw_session_id=session_id,
                model=agg.get("model"),
                cwd=agg.get("cwd"),
                tokens_in=delta["input"] + delta["cache_read"],
                tokens_out=delta["output"],
                flags=new_flags or None,
                ts=agg.get("last_ts") if ts_from_transcript else None,
            )
            out.append(ev)
            agg["emitted_tokens"] = dict(agg["tokens"])
            if scan_content:
                agg["emitted_flags"] = [_flag_key(f) for f in agg["flags"]]
            emitted += 1

        # Tool-call deltas (AIM-86 / AIM-627), emitted independently of token
        # deltas: a tool_use event goes out even when the token delta is zero.
        # Prefer discrete chain invocations when tool_use ids were present;
        # fall back to aggregate (server|tool) counts for id-less transcripts.
        inv = agg.setdefault("invocations", [])
        emitted_inv = agg.setdefault("emitted_invocation_count", 0)
        delta_calls = []
        delta_handoffs = []
        if len(inv) > emitted_inv:
            for entry in inv[emitted_inv:]:
                row = {
                    "tool_name": entry["tool_name"],
                    "mcp_server": entry["mcp_server"],
                    "action_class": entry["action_class"],
                    "count": 1,
                    "duration_ms": entry.get("duration_ms"),
                    "call_id": entry["call_id"],
                    "parent_call_id": entry.get("parent_call_id"),
                    "result_status": entry.get("result_status") or "unknown",
                    "seq": entry.get("seq", 0),
                }
                delta_calls.append(row)
            # Handoffs that became terminal or newly started since last emit.
            handoffs = agg.setdefault("handoffs", [])
            emitted_h = agg.setdefault("emitted_handoff_count", 0)
            for h in handoffs[emitted_h:]:
                delta_handoffs.append({
                    "handoff_kind": h["handoff_kind"],
                    "status": h["status"],
                    "child_session_id": h.get("child_session_id"),
                    "tool_name": h.get("tool_name"),
                    "parent_call_id": h.get("parent_call_id"),
                })
            # Also re-emit status updates for handoffs that completed after start
            # was already emitted: scan earlier handoffs for terminal status
            # not yet flushed (track via _emitted_status).
            for h in handoffs[:emitted_h]:
                prev = h.get("_emitted_status")
                if prev != h.get("status") and h.get("status") in ("completed", "failed", "cancelled"):
                    delta_handoffs.append({
                        "handoff_kind": h["handoff_kind"],
                        "status": h["status"],
                        "child_session_id": h.get("child_session_id"),
                        "tool_name": h.get("tool_name"),
                        "parent_call_id": h.get("parent_call_id"),
                    })
                    h["_emitted_status"] = h["status"]
            for h in handoffs[emitted_h:]:
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
            ev = events.new_tool_use_event(
                raw_session_id=session_id,
                model=agg.get("model"),
                cwd=agg.get("cwd"),
                tool_calls=delta_calls,
                agent_handoffs=delta_handoffs or None,
                ts=agg.get("last_ts") if ts_from_transcript else None,
            )
            out.append(ev)
            for key, entry in tool_calls.items():
                emitted_calls[key] = entry["count"]
            if len(inv) > emitted_inv:
                agg["emitted_invocation_count"] = len(inv)
                agg["emitted_handoff_count"] = len(agg.setdefault("handoffs", []))
            emitted += 1

    # JSON checkpoint: sets are not serializable.
    for _sid, _agg in aggs.items():
        if isinstance(_agg.get("seen_tool_use_ids"), set):
            _agg["seen_tool_use_ids"] = sorted(_agg["seen_tool_use_ids"])
    # MCP server config inventory (AIM-97/AIM-570): one event when the
    # configured (name, scope) set changed. Workspace paths come from
    # session cwd fragments already in the checkpoint (never re-emitted).
    try:
        workspaces = [
            st["cwd"] for st in aggs.values()
            if isinstance(st, dict) and isinstance(st.get("cwd"), str)
        ]
        inv_ev = mcp_inventory.scan(cp, workspaces=workspaces)
    except Exception:
        inv_ev = None  # inventory failure must not stall usage collection
    if inv_ev is not None:
        out.append(inv_ev)
        emitted += 1

    state.save_checkpoint(cp, checkpoint)
    sink(out)
    return emitted


def watch(interval: float = 30.0) -> None:
    """Daemon loop. Runs until killed (Intune/scheduled task manages it)."""
    from . import enroll
    last_hb = 0.0  # first iteration heartbeats immediately (liveness on start)
    while True:
        sleep_for = interval
        try:
            scan_once()
            res = spool.flush()
            # Honour ingest backpressure (AIM-127): when the service sheds with
            # 429/Retry-After, wait at least the requested window before the next
            # attempt so we don't hammer an overloaded ingest node.
            retry_after = res.get("retry_after") if isinstance(res, dict) else None
            if isinstance(retry_after, (int, float)) and retry_after > 0:
                sleep_for = max(interval, float(retry_after))
            last_hb = enroll.maybe_heartbeat(last_hb)
        except Exception:
            pass  # stay alive; a collector must not crash-loop visibly
        time.sleep(sleep_for)
