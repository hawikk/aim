"""Hook entrypoint: convert a Cursor hook payload (stdin JSON) into
metadata-only v1 events.

Cursor runs ``python -m cursor_collector hook <event-name>`` and pipes a
JSON payload on stdin. Payload fields vary by event and Cursor version, so
extraction is defensive: take what exists, tolerate everything missing.

We never block (always exit 0, no stdout contract) — enforcement is
observe-only per locked posture, and a slow/broken collector must never
break an engineer's tool.
"""

import json
import sys
import uuid

from . import events, matchers, pricing, spool, state  # noqa: F401 (state used by _cached_tool_version)

# Events we register for / accept (install.py registers exactly these).
HOOK_EVENTS = (
    "sessionStart",
    "sessionEnd",
    "beforeSubmitPrompt",
    "afterAgentResponse",
    "postToolUse",
)

# Payload fields that may carry content. Scanned locally, flags only.
_CONTENT_FIELDS = ("prompt", "prompt_text", "input", "tool_input",
                   "tool_output", "response", "text", "result")

# Candidate keys for the conversation/session id — Cursor versions differ.
_SESSION_KEYS = ("conversation_id", "session_id", "chat_id", "conversationId")


def _session_id(payload: dict) -> str | None:
    for k in _SESSION_KEYS:
        v = payload.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _cwd(payload: dict) -> str | None:
    roots = payload.get("workspace_roots") or payload.get("workspaceRoots")
    if isinstance(roots, list) and roots and isinstance(roots[0], str):
        return roots[0]
    cwd = payload.get("cwd")
    return cwd if isinstance(cwd, str) and cwd else None


def _str_field(payload: dict, *keys: str) -> str | None:
    for k in keys:
        v = payload.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _tokens(payload: dict) -> tuple[int | None, int | None]:
    """Token counts when the payload carries them (rare from hooks)."""
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        usage = payload
    def _int(*keys):
        for k in keys:
            v = usage.get(k)
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0:
                return int(v)
        return None
    return (_int("tokens_in", "input_tokens", "prompt_tokens"),
            _int("tokens_out", "output_tokens", "completion_tokens"))


def _duration_ms(payload: dict) -> int | None:
    """postToolUse carries execution time as `duration` (ms); accept
    `duration_ms` too, tolerate anything else."""
    for k in ("duration", "duration_ms"):
        v = payload.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0:
            return int(v)
    return None


def handle_payload(event_name: str, payload: dict) -> list[dict]:
    """One usage event per hook invocation, plus one tool_use event for
    postToolUse payloads that name a tool (AIM-86). [] when the hook is
    unregistered or the payload carries no session id (can't correlate,
    so drop)."""
    if event_name not in HOOK_EVENTS:
        return []
    if not isinstance(payload, dict):
        return []
    raw_session = _session_id(payload)
    if not raw_session:
        return []

    flags = []
    for field in _CONTENT_FIELDS:
        flags += matchers.scan_obj_matches(payload.get(field))

    model = _str_field(payload, "model", "model_name", "modelName")
    tokens_in, tokens_out = _tokens(payload)
    cost = pricing.estimate_cost(model, tokens_in, tokens_out)

    ev = events.new_event(
        raw_session_id=raw_session,
        model=model,
        cwd=_cwd(payload),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_estimate_usd=cost,
        flags=flags,
        tool_version=_cached_tool_version(),
    )
    out = [ev]

    # AIM-86: postToolUse fires for every agent tool (built-in and MCP)
    # and carries tool_name + duration. Only the name survives — arguments
    # (tool_input) and results (tool_output) are scanned for flags above
    # and then dropped; they are never read into the event.
    # AIM-627: emit chain fields (call_id/seq/result_status) + agent_handoffs
    # for Task/Agent tools. Metadata only — never args or result bodies.
    if event_name == "postToolUse":
        tool_name = payload.get("tool_name")
        if isinstance(tool_name, str) and tool_name.strip():
            call_id, result_status, seq = _chain_fields(payload, raw_session, tool_name)
            entry = events.tool_call_entry(
                tool_name,
                count=1,
                duration_ms=_duration_ms(payload),
                call_id=call_id,
                parent_call_id=None,
                result_status=result_status,
                seq=seq,
            )
            handoffs = None
            kind = events.handoff_kind_for(entry["tool_name"])
            if kind:
                handoffs = [{
                    "handoff_kind": kind,
                    "status": "failed" if result_status == "error" else "completed",
                    "child_session_id": None,
                    "tool_name": entry["tool_name"][:64],
                    "parent_call_id": call_id,
                }]
            out.append(events.new_tool_use_event(
                raw_session_id=raw_session,
                model=model,
                cwd=_cwd(payload),
                flags=flags,
                tool_version=_cached_tool_version(),
                tool_calls=[entry],
                agent_handoffs=handoffs,
            ))
    return out


def _chain_fields(payload: dict, raw_session: str, tool_name: str) -> tuple[str, str, int]:
    """Derive opaque call_id + result_status + seq for a postToolUse event.

    Prefer framework tool-call ids when present (tool_call_id / toolCallId /
    call_id / generation_id). Otherwise synthesize from session + tool name
    + a stable payload fingerprint of non-content keys. Never hashes args
    or results. result_status uses is_error / failed / success when present;
    postToolUse without error signal → ok.
    """
    raw_id = None
    for k in ("tool_call_id", "toolCallId", "call_id", "callId",
              "generation_id", "generationId", "tool_use_id", "toolUseId"):
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            raw_id = v.strip()
            break
    if not raw_id:
        # No framework id — opaque id from session + tool name + duration only
        # (no content). uuid4 suffix keeps distinct postToolUse of same tool
        # in the same second from colliding when no id is available.
        dur = _duration_ms(payload)
        raw_id = f"{raw_session}|{tool_name.strip()}|{dur if dur is not None else ''}|{uuid.uuid4().hex[:12]}"
    call_id = events.opaque_call_id(raw_id)

    result_status = "ok"
    if payload.get("is_error") is True or payload.get("failed") is True:
        result_status = "error"
    elif payload.get("is_error") is False or payload.get("success") is True:
        result_status = "ok"
    elif "status" in payload and isinstance(payload.get("status"), str):
        st = payload["status"].strip().lower()
        if st in ("error", "failed", "failure"):
            result_status = "error"
        elif st in ("ok", "success", "completed", "done"):
            result_status = "ok"
        elif st in ("denied", "blocked", "cancelled", "canceled"):
            result_status = "denied" if st in ("denied", "blocked") else "unknown"

    # Monotonic per-process seq is fine for timeline ordering within a
    # session window; not persisted (Cursor hooks are event-at-a-time).
    seq = int(getattr(_chain_fields, "_seq", 0))
    _chain_fields._seq = seq + 1  # type: ignore[attr-defined]
    return call_id, result_status, seq


def _cached_tool_version() -> str | None:
    f = state.state_dir() / "tool_version"
    try:
        return f.read_text().strip() or None
    except OSError:
        return None


def main(argv=None) -> int:
    try:
        args = list(sys.argv[1:] if argv is None else argv)
        event_name = args[0] if args else ""
        raw = sys.stdin.buffer.read(1 * 1024 * 1024)  # hooks are small; cap anyway
        payload = json.loads(raw or b"{}")
        evs = handle_payload(event_name, payload)
        spool.append(evs)
        # Best-effort opportunistic flush; failure is fine, spool persists.
        spool.flush()
    except Exception:
        # A collector must never break the engineer's session.
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
