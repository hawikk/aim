"""Cursor hook stdout adapter for AIM endpoint enforcement.

Reuses ``aim_collector.enforce`` (same ``enforcement.json``, same Decision
engine). Emits **Cursor** hook JSON only — never Claude's ``decision`` /
``permissionDecision`` shapes.

Official Cursor contract (cursor.com/docs/hooks, 2026-08-17):

- ``beforeSubmitPrompt``: ``{"continue": false, "user_message": "..."}``
- ``preToolUse``: ``{"permission": "deny"|"allow", "user_message", "agent_message",
  "updated_input"?}``
- ``beforeShellExecution`` / ``beforeMCPExecution``:
  ``{"permission": "allow"|"deny"|"ask", "user_message", "agent_message"}``

Blocking also requires exit status 2 and valid JSON. Observe: exit 0, no
stdout. Fail-open: any error → no decision (caller exits 0).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Detector names are fine in user_message; credential literals are not.
_SECRETISH = re.compile(
    r"AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|sk-[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
)

_SESSION_KEYS = ("conversation_id", "session_id", "chat_id", "conversationId")


def _import_aim():
    """Import aim_collector.enforce / matchers the way personal.py loads siblings."""
    collectors = Path(__file__).resolve().parents[2]  # .../collectors
    claude = collectors / "claude-code"
    if claude.is_dir() and str(claude) not in sys.path:
        sys.path.insert(0, str(claude))
    from aim_collector import enforce, matchers  # noqa: WPS433 — sibling package
    return enforce, matchers


def _session_id(payload: dict) -> str:
    for k in _SESSION_KEYS:
        v = payload.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _prompt(payload: dict) -> str | None:
    for k in ("prompt", "prompt_text"):
        v = payload.get(k)
        if isinstance(v, str):
            return v
    return None


def _tool_name(payload: dict) -> str:
    v = payload.get("tool_name")
    return v if isinstance(v, str) else ""


def _as_tool_input(raw) -> dict:
    """Normalize Cursor tool_input (object or JSON string) to a dict."""
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


def _mcp_tool_name(payload: dict) -> str:
    """Prefer an ``mcp__server__tool`` name so unapproved-mcp-server can fire.

    Cursor's beforeMCPExecution input may send a bare tool name plus url/command.
    Unknown server counts as unapproved (same as Claude's engine).
    """
    name = _tool_name(payload)
    if name.startswith("mcp__"):
        return name
    server = payload.get("mcp_server") or payload.get("server")
    if isinstance(server, str) and server.strip() and name:
        return f"mcp__{server.strip()}__{name}"
    if name:
        return f"mcp__unknown__{name}"
    return "mcp__unknown__unknown"


def to_claude_payload(event_name: str, payload: dict) -> dict | None:
    """Map a Cursor hook event + stdin payload to a Claude-shaped enforce payload."""
    if not isinstance(payload, dict):
        return None
    sid = _session_id(payload)
    if event_name == "beforeSubmitPrompt":
        return {
            "hook_event_name": "UserPromptSubmit",
            "prompt": _prompt(payload) or "",
            "session_id": sid,
        }
    if event_name == "beforeShellExecution":
        cmd = payload.get("command") if isinstance(payload.get("command"), str) else ""
        cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else ""
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": "Shell",
            "tool_input": {"command": cmd, "cwd": cwd},
            "session_id": sid,
        }
    if event_name == "preToolUse":
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": _tool_name(payload),
            "tool_input": _as_tool_input(payload.get("tool_input")),
            "session_id": sid,
        }
    if event_name == "beforeMCPExecution":
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": _mcp_tool_name(payload),
            "tool_input": _as_tool_input(payload.get("tool_input")),
            "session_id": sid,
        }
    return None


def decide(event_name: str, payload: dict):
    """Return an ``enforce.Decision`` or None. Never raises."""
    try:
        enforce, matchers = _import_aim()
        pol = enforce.load_policy()
        if not pol:
            return None
        mapped = to_claude_payload(event_name, payload)
        if not mapped:
            return None
        if mapped.get("hook_event_name") == "UserPromptSubmit":
            prompt = mapped.get("prompt")
            flags = matchers.scan_obj(prompt)
            return enforce.decide_user_prompt_submit(
                prompt, flags, pol, mapped.get("session_id") or "",
            )
        if mapped.get("hook_event_name") == "PreToolUse":
            return enforce.decide_pretool_use(mapped, pol)
        return None
    except Exception:
        return None


def _safe_user_message(decision) -> str:
    """User/agent-visible reason. Never includes credential literals."""
    reason = getattr(decision, "reason", None)
    if not isinstance(reason, str) or not reason.strip():
        return "Blocked by AI Monitoring."
    if _SECRETISH.search(reason):
        return "Blocked by AI Monitoring."
    return reason


def cursor_stdout(decision, event_name: str) -> dict:
    """Cursor hook JSON for a Decision. Empty dict = do not print."""
    action = getattr(decision, "action", None)
    if action == "redacted":
        # preToolUse is the only Cursor hook with updated_input.
        if event_name == "preToolUse" and isinstance(
                getattr(decision, "updated_input", None), dict):
            return {
                "permission": "allow",
                "updated_input": decision.updated_input,
            }
        return {}
    if action != "blocked":
        return {}
    msg = _safe_user_message(decision)
    if event_name == "beforeSubmitPrompt":
        return {"continue": False, "user_message": msg}
    # preToolUse / beforeShellExecution / beforeMCPExecution
    return {
        "permission": "deny",
        "user_message": msg,
        "agent_message": msg,
    }
