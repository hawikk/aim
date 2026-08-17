"""Hook entrypoint: convert a Claude Code hook payload (stdin JSON) into
metadata-only v1 events — and, since AIM-110 Phase 1, compute endpoint
enforcement decisions for the approved critical rules (AIM-111 Phase 2a
adds restricted-repo-access and the pii-in-prompt confirm-prompt behind
the same enforce flags, shadow-first).

Registered events: SessionStart, SessionEnd, PostToolUse, UserPromptSubmit,
PreToolUse (PreToolUse is telemetry-inert — it exists only to deny MCP calls
to unapproved servers, deny restricted-repo paths, and (AIM-320) redact
secrets from tool inputs via updatedInput; PostToolUse remains the telemetry
rail).

Enforcement posture (AIM-15 amended 2026-07-22, board-approved): observe +
endpoint blocking for critical rules. Fail-open is a hard requirement: any
error in the decision path (missing/malformed policy, matcher exception,
audit-event failure) degrades to observe — exit 0, no decision output. A
slow/broken collector must never break an engineer's tool.
"""

import json
import sys
import time

from . import events, matchers, spool, state  # noqa: F401 (state used by _cached_tool_version)

# PostToolUse/UserPromptSubmit payloads contain content (tool_input, prompt).
# We scan locally and keep only flags.
_CONTENT_FIELDS = ("tool_input", "tool_response", "prompt")

# Coarse action classes (mirrors transcript.py; keep in sync).
_ACTION_CLASS = {
    "Read": "fs_read", "Glob": "fs_read", "Grep": "fs_read",
    "LS": "fs_read", "NotebookRead": "fs_read",
    "Write": "fs_write", "Edit": "fs_write", "MultiEdit": "fs_write",
    "NotebookEdit": "fs_write",
    "Bash": "shell", "BashOutput": "shell", "KillShell": "shell",
    "WebFetch": "network", "WebSearch": "network",
}
_HANDOFF_TOOL_KIND = {
    "Task": "task", "Agent": "subagent", "TaskCreate": "task", "TaskTool": "task",
}


def _split_tool_name(name: str) -> tuple[str, str | None]:
    if name.startswith("mcp__"):
        parts = name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return parts[2][:64], parts[1][:128]
    return name[:64], None


def _opaque_call_id(raw_id: str) -> str:
    """Daily-stable opaque call id (AIM-627/799). Same salt family as session_id."""
    from datetime import datetime, timezone
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return events.session_id(f"call|{raw_id}", day=day)[:32]


def _post_tool_use_chain(payload: dict, *, session_id: str, cwd, flags, tool_version) -> list[dict]:
    """AIM-799: PostToolUse → tool_use event with optional chain + handoff
    metadata when the framework exposes tool ids. Never reads tool_input /
    tool_response bodies into the event (only flags, already scanned)."""
    raw_name = payload.get("tool_name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        return []
    tool, server = _split_tool_name(raw_name.strip())
    action = "mcp_call" if server else _ACTION_CLASS.get(tool, "other")
    row = {
        "tool_name": tool,
        "mcp_server": server,
        "action_class": action,
        "count": 1,
        "duration_ms": None,
        "result_status": "unknown",
        "seq": 0,
    }
    # Duration when the hook reports a numeric wall time (never content).
    for k in ("duration_ms", "durationMs", "elapsed_ms"):
        v = payload.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0:
            row["duration_ms"] = int(v)
            break
    # Coarse result status from metadata flags only — never body text.
    is_err = payload.get("is_error")
    if is_err is None and isinstance(payload.get("tool_response"), dict):
        is_err = payload["tool_response"].get("is_error")
    if is_err is True:
        row["result_status"] = "error"
    elif is_err is False:
        row["result_status"] = "ok"

    raw_call = payload.get("tool_use_id") or payload.get("tool_call_id") or payload.get("call_id")
    if isinstance(raw_call, str) and raw_call.strip():
        row["call_id"] = _opaque_call_id(raw_call.strip())
    raw_parent = payload.get("parent_tool_use_id") or payload.get("parent_call_id")
    if isinstance(raw_parent, str) and raw_parent.strip():
        row["parent_call_id"] = _opaque_call_id(raw_parent.strip())
    else:
        row["parent_call_id"] = None

    agent_handoffs = None
    handoff_kind = _HANDOFF_TOOL_KIND.get(tool) or _HANDOFF_TOOL_KIND.get(raw_name.strip())
    if handoff_kind:
        status = (
            "failed" if row["result_status"] == "error"
            else "completed" if row["result_status"] == "ok"
            else "started"
        )
        agent_handoffs = [{
            "handoff_kind": handoff_kind,
            "status": status,
            "child_session_id": None,
            "tool_name": tool,
            "parent_call_id": row.get("call_id"),
        }]

    return [events.new_tool_use_event(
        raw_session_id=session_id,
        model=None,
        cwd=cwd,
        tool_calls=[row],
        tool_version=tool_version,
        agent_handoffs=agent_handoffs,
    )]


def handle_payload(payload: dict) -> list[dict]:
    hook_name = payload.get("hook_event_name", "")
    session_id = payload.get("session_id")
    cwd = payload.get("cwd")

    # Local scan of any content-bearing fields; occurrences are fingerprinted
    # by events.make_flags and the matched text is discarded (AIM-225).
    flags = []
    for field in _CONTENT_FIELDS:
        flags += matchers.scan_obj_matches(payload.get(field))

    tool_version = _cached_tool_version()

    # PreToolUse fires per tool call; telemetry for tool calls comes from
    # PostToolUse / the transcript watcher, so PreToolUse stays observe-inert
    # here (its only job is the enforcement decision in run()).
    if hook_name not in ("SessionStart", "SessionEnd", "PostToolUse", "UserPromptSubmit"):
        return []  # unregistered event; ignore quietly
    if not session_id:
        return []

    # Schema v1 has no event_type field (gap raised on AIM-18 for v1.1);
    # hook events carry session/flags/tool identity, token volume comes
    # from the transcript watcher.
    ev = events.new_event(raw_session_id=session_id, model=None, cwd=cwd,
                          flags=flags, tool_version=tool_version)
    out = [ev]
    # AIM-799: PostToolUse also emits a discrete tool_use row with chain
    # fields when tool_name (and optional tool_use_id) are present.
    if hook_name == "PostToolUse":
        out.extend(_post_tool_use_chain(
            payload, session_id=session_id, cwd=cwd, flags=flags,
            tool_version=tool_version))
    return out


def _cached_tool_version() -> str | None:
    f = state.state_dir() / "tool_version"
    try:
        return f.read_text().strip() or None
    except OSError:
        return None


def _enforcement_decision(payload: dict):
    """Compute (policy, orchestrated, evaluated) for this payload. Never raises:
    fail-open means any error here is an observe.

    `orchestrated` is None when no rule fired; the policy and the `evaluated`
    flag are returned regardless, because the coverage marker has to be
    emitted exactly when nothing fires — that is the case the bake cannot
    otherwise distinguish from "no collector here".

    AIM-782: multi-rail orchestration returns a single primary Decision plus
    ordered rail attribution. Deterministic precedence lives in
    ``enforce.RAIL_PRECEDENCE`` / ``docs/security/multi-rail-precedence.md``
    — never short-circuit in a way that could emit two denials.
    """
    from . import enforce
    pol = enforce.load_policy()
    hook_name = payload.get("hook_event_name", "")
    evaluated = hook_name in enforce.EVALUATED_HOOKS
    if hook_name == "UserPromptSubmit":
        # Decision scans the prompt field only. prompt + session_id are
        # required for AIM-296 secret break-glass and the PII confirm path.
        prompt = payload.get("prompt")
        flags = matchers.scan_obj(prompt)
        orchestrated = enforce.orchestrate(payload, pol, prompt_flags=flags)
    elif hook_name == "PreToolUse":
        # Decision C multi-rail (MCP + restricted-repo). Redact (AIM-320)
        # remains outside Decision C multi-rail and only runs when neither
        # MCP nor restricted-repo fired — same short-circuit order as main.
        orchestrated = enforce.orchestrate(payload, pol)
        if orchestrated is None:
            redact = enforce.decide_redact_tool_input(payload, pol)
            if redact is not None:
                orchestrated = redact
    else:
        return pol, None, False
    return pol, orchestrated, evaluated


def _apply_decision(evs: list[dict], payload: dict, pol: dict, orchestrated) -> list[dict]:
    """Attach the metadata-only audit record (schema v1.5 `enforcement`,
    v1.11 multi-rail ``rails`` attribution) to the telemetry event when one
    exists; otherwise emit a standalone audit event. Never carries content:
    action + rule id + policy hash (+ optional rails) only."""
    from . import enforce
    decision = orchestrated.decision if hasattr(orchestrated, "decision") else orchestrated
    rails = getattr(orchestrated, "rails", None)
    rec = enforce.audit_record(pol, decision, rails=rails)
    if evs:
        evs[0]["enforcement"] = rec
        events.validate(evs[0])
        return evs
    session_id = payload.get("session_id")
    if not session_id:
        return []  # decision still applies; we just cannot audit it
    flags = matchers.scan_obj_matches(payload.get("tool_input"))
    ev = events.new_event(raw_session_id=session_id, model=None,
                          cwd=payload.get("cwd"), flags=flags,
                          tool_version=_cached_tool_version(),
                          enforcement=rec)
    return [ev]


def _attach_posture(
    evs: list[dict],
    pol: dict,
    evaluated: bool,
    *,
    enforcement_latency_ms: int | None = None,
) -> None:
    """Stamp the schema v1.7 coverage marker on every event we are about to
    spool. Best-effort and isolated: posture is bookkeeping, so a failure here
    must not drop telemetry or a block decision.

    AIM-790: when the decision path ran (``evaluated``), also stamp
    ``enforcement_latency_ms`` under posture — metadata-only wall time for the
    design SLO (p95 < 200 ms). Fail-open timeout stays a separate budget."""
    from . import enforce
    lat = enforcement_latency_ms if evaluated else None
    rec = enforce.posture_record(pol, evaluated, enforcement_latency_ms=lat)
    for ev in evs:
        ev["enforcement_posture"] = dict(rec)
        events.validate(ev)


def run(raw: bytes) -> tuple[int, str]:
    """Hook core: payload bytes in, (exit code, stdout) out. Never raises —
    the outer contract with the engineer's tool is fail-open."""
    try:
        payload = json.loads(raw or b"{}")
        evs = handle_payload(payload)
        decision_out = ""
        pol, evaluated = {}, False
        latency_ms: int | None = None
        try:
            # AIM-790: wall time for the local decision path only (policy load
            # + rule evaluation + audit attach). Spool/flush is out of scope —
            # that is async bookkeeping, not the engineer's block latency.
            t0 = time.perf_counter()
            pol, orchestrated, evaluated = _enforcement_decision(payload)
            if orchestrated is not None:
                evs = _apply_decision(evs, payload, pol, orchestrated)
                decision = (
                    orchestrated.decision
                    if hasattr(orchestrated, "decision")
                    else orchestrated
                )
                if decision.action == "blocked":
                    from . import enforce
                    decision_out = json.dumps(enforce.deny_output(decision)) + "\n"
                elif decision.action == "redacted":
                    from . import enforce
                    decision_out = json.dumps(enforce.redact_output(decision)) + "\n"
            # Clamp to schema max; sub-ms rounds to 0 (still a valid sample).
            latency_ms = min(60000, max(0, int((time.perf_counter() - t0) * 1000)))
        except Exception:
            # Fail-open on any matcher/policy/audit error: the event stream
            # from handle_payload still stands, no decision is emitted.
            # Leave latency_ms unset — a failed path must not claim a clean
            # measured sample for the SLO denominator.
            decision_out = ""
            latency_ms = None
        try:
            _attach_posture(evs, pol, evaluated, enforcement_latency_ms=latency_ms)
        except Exception:
            # Uncovered is the honest reading of a posture we could not build;
            # never trade a real event or a real block for the marker.
            for ev in evs:
                ev.pop("enforcement_posture", None)
        spool.append(evs)
        # Best-effort opportunistic flush; failure is fine, spool persists.
        spool.flush()
        return 0, decision_out
    except Exception:
        # A collector must never break the engineer's session.
        return 0, ""


def main() -> int:
    raw = sys.stdin.buffer.read(1 * 1024 * 1024)  # hooks are small; cap anyway
    code, out = run(raw)
    if out:
        sys.stdout.write(out)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
