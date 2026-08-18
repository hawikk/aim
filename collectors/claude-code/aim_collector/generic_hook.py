"""Shared stdin-hook enforcement for Claude-shaped vendor payloads.

Copilot (VS Code / Copilot CLI), Kimi Code, and Grok Build all send JSON
on stdin with ``hook_event_name`` (or camelCase) plus ``prompt`` /
``tool_name`` / ``tool_input``. This module maps that onto
``aim_collector.enforce`` and emits the vendor's own stdout contract.

Fail-open: missing policy, matcher errors, and collector bugs return
``(0, "", "")`` — never break the engineer's session.
"""

from __future__ import annotations

import json
import re

_SECRETISH = re.compile(
    r"AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|sk-[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
)

_PROMPT_EVENTS = {
    "userpromptsubmit",
    "userpromptsubmitted",
    "user_prompt_submit",
}
_TOOL_EVENTS = {
    "pretooluse",
    "pre_tool_use",
}


def _norm_event(payload: dict) -> str:
    raw = payload.get("hook_event_name") or payload.get("hookEventName") or ""
    if raw:
        return str(raw).replace("-", "").replace("_", "").lower()
    # Copilot CLI camelCase payloads omit the event name.
    if _tool_name(payload):
        return "pretooluse"
    if _prompt(payload):
        return "userpromptsubmit"
    return ""


def _session_id(payload: dict) -> str:
    for k in ("session_id", "sessionId", "conversation_id", "conversationId"):
        v = payload.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _prompt(payload: dict) -> str:
    for k in ("prompt", "prompt_text", "user_prompt"):
        v = payload.get(k)
        if isinstance(v, str):
            return v
    return ""


def _tool_name(payload: dict) -> str:
    v = payload.get("tool_name") or payload.get("toolName")
    return v if isinstance(v, str) else ""


def _tool_input(payload: dict) -> dict:
    raw = payload.get("tool_input")
    if raw is None:
        raw = payload.get("toolInput")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        return {"_raw": raw}
    return {}


def safe_reason(decision) -> str:
    reason = getattr(decision, "reason", None)
    if not isinstance(reason, str) or not reason.strip():
        return "Blocked by AI Monitoring."
    if _SECRETISH.search(reason):
        return "Blocked by AI Monitoring."
    return reason


def decide(payload: dict):
    """Return an ``enforce.Decision`` or None. Never raises."""
    try:
        from aim_collector import enforce, matchers
        pol = enforce.load_policy()
        if not pol:
            return None
        ev = _norm_event(payload)
        sid = _session_id(payload)
        if ev in _PROMPT_EVENTS:
            prompt = _prompt(payload)
            flags = matchers.scan_obj(prompt)
            return enforce.decide_user_prompt_submit(prompt, flags, pol, sid)
        if ev in _TOOL_EVENTS:
            mapped = {
                "hook_event_name": "PreToolUse",
                "tool_name": _tool_name(payload),
                "tool_input": _tool_input(payload),
                "session_id": sid,
            }
            return enforce.decide_pretool_use(mapped, pol)
        return None
    except Exception:
        return None


def emit(vendor: str, decision, payload: dict) -> tuple[int, str, str]:
    """``(exit_code, stdout, stderr)`` for a Decision. Fail-open if unused."""
    action = getattr(decision, "action", None)
    if action != "blocked":
        return 0, "", ""
    msg = safe_reason(decision)
    ev = _norm_event(payload)
    if vendor == "grok":
        # Official xAI contract: only PreToolUse is blocking.
        if ev not in _TOOL_EVENTS:
            return 0, "", ""
        return 2, json.dumps({"decision": "deny", "reason": msg}) + "\n", ""
    if vendor == "kimi":
        body = {
            "hookSpecificOutput": {
                "permissionDecision": "deny",
                "permissionDecisionReason": msg,
            }
        }
        return 2, json.dumps(body) + "\n", msg + "\n"
    # Copilot VS Code / Copilot CLI / Claude-compatible JSON.
    if ev in _PROMPT_EVENTS:
        body = {"continue": False, "stopReason": msg, "systemMessage": msg}
        return 2, json.dumps(body) + "\n", ""
    body = {
        "hookSpecificOutput": {
            "permissionDecision": "deny",
            "permissionDecisionReason": msg,
        }
    }
    return 2, json.dumps(body) + "\n", ""


def run(vendor: str, raw: bytes) -> tuple[int, str, str]:
    """Parse stdin bytes, decide, emit. Never raises."""
    try:
        payload = json.loads(raw or b"{}")
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        return 0, "", ""
    decision = decide(payload)
    if decision is None:
        return 0, "", ""
    try:
        return emit(vendor, decision, payload)
    except Exception:
        return 0, "", ""
