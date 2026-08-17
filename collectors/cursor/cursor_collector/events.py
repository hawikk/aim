"""Canonical event construction, conforming to the ratified schema:
packages/schema/schema/v1/ai-usage-event.schema.json.

Content policy (locked): no prompt text, tool input/output, file
contents, or code on an event. Ingest rejects out-of-schema fields whole,
so everything emitted here must validate against the schema.

Cursor-specific notes:
- Cursor conversation ids are long-lived (chats persist across days), so
  raw session ids are re-hashed per UTC day as the schema's session_id
  description requires: HMAC(utc-date || raw_id). Events cannot be
  profiled across days.
- Unlike claude-code, cost_estimate_usd IS sent when token counts are
  observable (pricing table in pricing.py) — Cursor hook payloads rarely
  carry tokens, so this fires mainly for the state.vscdb path.
"""

import hashlib
import hmac
import json
import os
import platform
import unicodedata
import uuid
from datetime import datetime, timezone

SCHEMA_VERSION = "1.10" # chain fields + agent_handoffs (was 1.1)
TOOL_NAME = "cursor"
MODEL_UNKNOWN = "unknown"  # schema requires `model` for source=endpoint

_ACTION_CLASSES = ("fs_read", "fs_write", "shell", "network", "mcp_call", "other")
_MCP_SERVER_KEYS = {"name", "scope"}
_MCP_SCOPES = ("user", "project")

_RESULT_STATUSES = ("ok", "error", "denied", "unknown")
_AGENT_HANDOFF_KEYS = {
    "handoff_kind", "status", "child_session_id", "tool_name", "parent_call_id",
}
_HANDOFF_KINDS = ("subagent", "task", "delegate", "other")
_HANDOFF_STATUSES = ("started", "completed", "failed", "cancelled")

# Tools that spawn sub-agents / Task loops (A2A handoffs).
# Cursor Task tool + common composer aliases — name only, never args.
_HANDOFF_TOOL_KIND = {
    "task": "task",
    "task_v2": "task",
    "agent": "subagent",
    "composer_agent": "subagent",
}

# Cursor built-in tool name -> coarse action class. Two vocabularies are
# covered: the current hook-payload names documented by Cursor (Shell,
# Read, Write, Grep, Delete, ...) and the older internal names seen in
# composer state (run_terminal_cmd, edit_file, read_file, ...). Matching
# is exact (case-insensitive); unknown names classify as "other" — never
# guess a capability class we can't support.
_TOOL_CLASS = {
    # fs_read: file reads / searches
    "read": "fs_read", "read_file": "fs_read", "ls": "fs_read",
    "list_dir": "fs_read", "grep": "fs_read", "grep_search": "fs_read",
    "file_search": "fs_read", "codebase_search": "fs_read",
    "search": "fs_read", "tabread": "fs_read",
    # fs_write: file edits / writes / deletes
    "write": "fs_write", "edit": "fs_write", "edit_file": "fs_write",
    "write_file": "fs_write", "delete": "fs_write", "delete_file": "fs_write",
    "reapply": "fs_write", "tabwrite": "fs_write",
    # shell: command execution
    "shell": "shell", "run_terminal_cmd": "shell",
    # network: web fetch / search
    "web_search": "network", "websearch": "network",
    "web_fetch": "network", "webfetch": "network", "fetch": "network",
}


def handoff_kind_for(tool_name: str) -> str | None:
    """Return handoff_kind enum value if tool_name is a Task/Agent spawn."""
    if not tool_name:
        return None
    return _HANDOFF_TOOL_KIND.get(tool_name.strip().lower())


def tool_call_entry(
    raw_name: str,
    *,
    count: int = 1,
    duration_ms: int | None = None,
    call_id: str | None = None,
    parent_call_id: str | None = None,
    result_status: str | None = None,
    seq: int | None = None,
) -> dict:
    """One metadata-only tool_calls[] entry from a raw Cursor tool name.

    MCP namespacing: ``mcp__<server>__<tool>`` is split so the schema's
    tool_name carries the tool part and mcp_server the server id; any MCP
    call classifies as mcp_call regardless of the tool part. Un-namespaced
    names are looked up in _TOOL_CLASS; unknown -> "other". Only the name
    is consumed — arguments/output never reach this function.

    chain fields (optional): call_id / parent_call_id / result_status /
    seq — opaque ids + coarse enums only; never args or result bodies.
    """
    name = raw_name.strip()
    mcp_server: str | None = None
    if name.startswith("mcp__"):
        parts = name.split("__")
        if len(parts) >= 3 and parts[1]:
            mcp_server = parts[1][:128]
            name = "__".join(parts[2:])
        action = "mcp_call"
    else:
        action = _TOOL_CLASS.get(name.lower(), "other")
    entry: dict = {
        "tool_name": (name or "unknown")[:64],
        "mcp_server": mcp_server,
        "action_class": action,
        "count": max(1, int(count)),
    }
    if duration_ms is not None and duration_ms >= 0:
        entry["duration_ms"] = int(duration_ms)
    else:
        entry["duration_ms"] = None
    if call_id is not None:
        entry["call_id"] = str(call_id)[:64]
    if parent_call_id is not None:
        entry["parent_call_id"] = str(parent_call_id)[:64]
    if result_status is not None:
        if result_status not in _RESULT_STATUSES:
            raise ValueError(f"bad result_status: {result_status!r}")
        entry["result_status"] = result_status
    if seq is not None:
        entry["seq"] = max(0, int(seq))
    return entry

# Category/severity mapping derived from detector name prefixes (matchers.py)
_CATEGORY = {"secret": "high", "pii": "medium", "injection": "medium", "policy": "low"}

_PROVIDER_PREFIXES = (
    ("claude", "anthropic"),
    ("gpt", "openai"),
    ("o1", "openai"), ("o3", "openai"), ("o4", "openai"), ("chatgpt", "openai"),
    ("gemini", "google"),
    ("grok", "xai"),
)


def _now_iso() -> str:
    # RFC 3339 with Z suffix (schema format: date-time)
    # schema ts pattern is second-precision: no fractional seconds
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _salt() -> bytes:
    """HMAC salt for pseudonymization.

    Schema intent: company-held salt in platform KMS. Dev/pilot deviation:
    read from AIM_HASH_SALT env or the managed config file (`hash_salt`
    key — the Intune-deployable distribution channel); if neither is set,
    fall back to a per-install random salt in the state dir (stable per
    device, not company-wide). Tracked as an integration item for
    (enrollment must distribute the real salt or move pseudonymization
    ingest-side).
    """
    s = os.environ.get("AIM_HASH_SALT")
    if s:
        return s.encode()
    from . import config
    s = config.hash_salt()
    if s:
        return s.encode()
    from . import state
    f = state.state_dir() / "pseudo_salt"
    if not f.exists():
        f.write_text(uuid.uuid4().hex)
        os.chmod(f, 0o600)
    return f.read_text().strip().encode()


def _hmac64(value: str) -> str:
    return hmac.new(_salt(), value.encode(), hashlib.sha256).hexdigest()


def host_ref() -> str:
    return _hmac64(platform.node() or "unknown-host")


def repo_ref(cwd: str | None) -> str | None:
    """HMAC of normalized workspace path (stand-in for the normalized repo
    URL until git-remote resolution lands; pseudonymized identically)."""
    if not cwd:
        return None
    norm = os.path.normpath(cwd).lower().replace("\\", "/")
    return _hmac64(norm)


def session_id(raw_id: str, day: str | None = None) -> str:
    """Re-hash a stable/long-lived tool session id per UTC day, as the
    schema requires: HMAC(utc-date || raw_id). `day` is injectable for
    tests; default is the current UTC date."""
    if day is None:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return _hmac64(f"{day}|{raw_id}")


def opaque_call_id(raw_tool_id: str) -> str:
    """Daily-stable opaque call_id from a framework tool id (never raw on wire)."""
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return session_id(f"call|{raw_tool_id}", day=day)[:32]


def derive_provider(model: str | None) -> str | None:
    """Best-effort provider from a model name; None when unobservable
    (Cursor routes many providers through one UI)."""
    if not model:
        return None
    name = model.strip().lower()
    for prefix, provider in _PROVIDER_PREFIXES:
        if name.startswith(prefix):
            return provider
    return None


# Categories whose matches get a redacted fingerprint. Injection
# detectors are prose patterns — fingerprinting phrasings adds no dedupe
# value, so they stay name-only.
_FP_CATEGORIES = ("secret", "pii")


def _fingerprint(detector: str, matched: str) -> str:
    """Redacted per-occurrence fingerprint: keyed, truncated HMAC of
    the NFKC-folded, whitespace-stripped match, domain-separated ("fp1") from
    the pseudonym HMACs so a fingerprint can never be cross-correlated with a
    host_ref/repo_ref of the same string. Stable while the company salt is
    unchanged, so repeat sightings of the same secret dedupe to one
    fingerprint; 64 bits is ample for a fleet. The matched text is discarded
    by the caller and never leaves the endpoint."""
    norm = "".join(unicodedata.normalize("NFKC", matched).split())
    return _hmac64(f"fp1|{detector}|{norm}")[:16]


def make_flags(flags: list) -> list[dict]:
    """Convert matcher output to schema match_flags entries.

    Accepts detector-name strings (enforcement path, tests) or
    matchers.Match occurrences. A Match from a secret/pii detector also
    carries fingerprint + offset + surface (schema v1.8) — enough to
    prove and dedupe the finding without storing the matched content.
    Pre-built entry dicts (personal-mode checkpoint deltas) pass through.
    Duplicates collapse on (detector, fingerprint)."""
    out = []
    seen = set()
    for item in flags:
        if isinstance(item, dict):
            # Pre-built entry: the personal-mode transcript checkpoint stores
            # fingerprinted flags as JSON and re-emits deltas. Pass through.
            entry = item
            fp = item.get("fingerprint")
        else:
            if isinstance(item, str):
                name, fp, offset, surface = item, None, None, None
            else:
                name = item.detector
                if name.split(":", 1)[0] in _FP_CATEGORIES:
                    fp = _fingerprint(name, item.matched)
                    offset, surface = item.offset, item.surface
                else:
                    fp = offset = surface = None
            category = name.split(":", 1)[0] if ":" in name else "policy"
            entry = {
                "detector": name[:64],
                "category": category if category in _CATEGORY else "policy",
                "severity": _CATEGORY.get(category, "low"),
            }
            if fp is not None:
                entry["fingerprint"] = fp
                entry["offset"] = offset
                entry["surface"] = surface
        key = (entry.get("detector"), fp)
        if key in seen:
            continue
        seen.add(key)
        out.append(entry)
    out.sort(key=lambda e: (e.get("detector") or "", e.get("fingerprint") or ""))
    return out


def _base_event(
    *,
    raw_session_id: str,
    model: str | None,
    cwd: str | None = None,
    flags: list[str] | None = None,
    tool_version: str | None = None,
) -> dict:
    model = (model or MODEL_UNKNOWN)[:128]
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": _now_iso(),
        "host_ref": host_ref(),
        "user_ref": None, # identity mapping not yet approved
        "tool": TOOL_NAME,
        "tool_version": (tool_version or "")[:64] or None,
        "model": model,
        "provider": derive_provider(model),
        "session_id": session_id(raw_session_id),
        "repo_ref": repo_ref(cwd),
        "match_flags": make_flags(flags or []),
        "source": "endpoint",
    }
    # strip None optionals the schema doesn't type as nullable
    for k in ("tool_version", "provider"):
        if ev[k] is None:
            del ev[k]
    return ev


def new_event(
    *,
    raw_session_id: str,
    model: str | None,
    cwd: str | None = None,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    cost_estimate_usd: float | None = None,
    flags: list[str] | None = None,
    tool_version: str | None = None,
) -> dict:
    ev = _base_event(raw_session_id=raw_session_id, model=model, cwd=cwd,
                     flags=flags, tool_version=tool_version)
    if tokens_in is not None:
        ev["tokens_in"] = int(tokens_in)
    if tokens_out is not None:
        ev["tokens_out"] = int(tokens_out)
    if cost_estimate_usd is not None:
        ev["cost_estimate_usd"] = float(cost_estimate_usd)
    validate(ev)
    return ev


def new_tool_use_event(
    *,
    raw_session_id: str,
    model: str | None,
    tool_calls: list[dict],
    cwd: str | None = None,
    flags: list[str] | None = None,
    tool_version: str | None = None,
    agent_handoffs: list[dict] | None = None,
) -> dict:
    """event_type='tool_use' event (schema v1.10). tool_calls
    entries must come from tool_call_entry() — names/classes/counts/durations
    + optional chain fields only. No token/cost fields: tool-call volume is
    not usage volume. agent_handoffs is metadata-only Task/subagent linkage."""
    if agent_handoffs:
        _validate_agent_handoffs(agent_handoffs)
    ev = _base_event(raw_session_id=raw_session_id, model=model, cwd=cwd,
                     flags=flags, tool_version=tool_version)
    ev["event_type"] = "tool_use"
    ev["tool_calls"] = tool_calls
    if agent_handoffs:
        ev["agent_handoffs"] = agent_handoffs
    validate(ev)
    return ev


def _validate_agent_handoffs(handoffs: list) -> None:
    """Schema v1.10 agent_handoffs[] guard — metadata only."""
    if not isinstance(handoffs, list):
        raise ValueError("agent_handoffs must be a list")
    if len(handoffs) > 100:
        raise ValueError("agent_handoffs is capped at 100 entries")
    for h in handoffs:
        if not isinstance(h, dict):
            raise ValueError("agent_handoffs entries must be objects")
        extra = set(h) - _AGENT_HANDOFF_KEYS
        if extra:
            raise ValueError(f"agent_handoffs entry out-of-schema keys: {sorted(extra)}")
        if h.get("handoff_kind") not in _HANDOFF_KINDS:
            raise ValueError(f"bad handoff_kind: {h.get('handoff_kind')!r}")
        if h.get("status") not in _HANDOFF_STATUSES:
            raise ValueError(f"bad handoff status: {h.get('status')!r}")
        for k, mx in (("child_session_id", 128), ("tool_name", 64), ("parent_call_id", 64)):
            v = h.get(k)
            if v is not None and (not isinstance(v, str) or len(v) > mx):
                raise ValueError(f"agent_handoffs.{k} must be null or string <={mx}")


def new_inventory_event(
    *,
    configured_mcp_servers: list[dict],
    tool_version: str | None = None,
) -> dict:
    """event_type='inventory' (schema v1.2): MCP servers
    present in Cursor config files. Emitted only when the configured set
    changes (change detection lives in mcp_inventory). Metadata-only: name
    + scope, never commands, args, URLs, or env values."""
    _validate_mcp_servers(configured_mcp_servers)
    host = host_ref()
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": _now_iso(),
        "host_ref": host,
        "user_ref": None,
        "tool": TOOL_NAME,
        "tool_version": (tool_version or "")[:64] or None,
        "model": None,
        "provider": None,
        "session_id": f"inv_{day}_{host[:12]}",
        "repo_ref": None,
        "event_type": "inventory",
        "configured_mcp_servers": [dict(s) for s in configured_mcp_servers],
        "match_flags": [],
        "source": "endpoint",
    }
    for k in ("tool_version",):
        if ev[k] is None:
            del ev[k]
    validate(ev)
    return ev

def validate(event: dict) -> None:
    """Local conformance check against the schema's hard constraints.
    Ingest-side JSON Schema validation remains authoritative."""
    required = ("schema_version", "event_id", "ts", "host_ref", "tool",
                "session_id", "source", "match_flags", "model")
    missing = [k for k in required if k not in event]
    if missing:
        raise ValueError(f"event missing required fields: {missing}")
    allowed = {
        "schema_version", "event_id", "ts", "host_ref", "user_ref",
        "tool", "tool_raw", "tool_version", "model", "provider",
        "session_id", "tokens_in", "tokens_out", "cost_estimate_usd",
        "repo_ref", "match_flags", "source", "event_type", "tool_calls",
        "agent_handoffs", "configured_mcp_servers",
        "enforcement", "enforcement_posture",
    }
    extra = set(event) - allowed
    if extra:
        raise ValueError(f"out-of-schema fields (ingest would reject): {sorted(extra)}")
    import re as _re
    if not _re.fullmatch(r"1\.[0-9]+", event["schema_version"]):
        raise ValueError("bad schema_version")
    et = event.get("event_type")
    if et is not None:
        if et not in ("usage", "tool_use", "inventory"):
            raise ValueError(f"bad event_type: {et!r}")
        if et == "tool_use":
            _validate_tool_calls(event.get("tool_calls"))
        if et == "inventory":
            if "configured_mcp_servers" not in event:
                raise ValueError("event_type='inventory' requires configured_mcp_servers")
    if "agent_handoffs" in event:
        _validate_agent_handoffs(event["agent_handoffs"])
    if "configured_mcp_servers" in event:
        _validate_mcp_servers(event["configured_mcp_servers"])
    for k in ("host_ref", "repo_ref"):
        v = event.get(k)
        if v is not None and not _re.fullmatch(r"[0-9a-f]{64}", str(v)):
            raise ValueError(f"{k} must be 64 lowercase hex chars")


def _validate_tool_calls(tool_calls) -> None:
    """Mirror the schema's tool_calls item constraints (v1.1):
    additionalProperties:false per entry, required keys, enums, bounds."""
    if not isinstance(tool_calls, list) or not tool_calls:
        raise ValueError("event_type=tool_use requires a non-empty tool_calls")
    allowed = {"tool_name", "action_class", "count", "mcp_server", "duration_ms", "call_id", "parent_call_id", "result_status", "seq"}
    for entry in tool_calls:
        if not isinstance(entry, dict):
            raise ValueError("tool_calls entries must be objects")
        extra = set(entry) - allowed
        if extra:
            raise ValueError(f"tool_calls entry out-of-schema fields: {sorted(extra)}")
        name = entry.get("tool_name")
        if not isinstance(name, str) or not name or len(name) > 64:
            raise ValueError("tool_calls.tool_name must be a string of <=64 chars")
        if entry.get("action_class") not in _ACTION_CLASSES:
            raise ValueError(f"bad action_class: {entry.get('action_class')!r}")
        count = entry.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise ValueError("tool_calls.count must be an int >= 1")
        server = entry.get("mcp_server")
        if server is not None and (not isinstance(server, str) or len(server) > 128):
            raise ValueError("tool_calls.mcp_server must be null or a string of <=128 chars")
        dur = entry.get("duration_ms")
        if dur is not None and (not isinstance(dur, int) or isinstance(dur, bool) or dur < 0):
            raise ValueError("tool_calls.duration_ms must be null or an int >= 0")

        # / schema v1.10 chain metadata (optional; never arguments/results).
        for _ck, _mx in (("call_id", 64), ("parent_call_id", 64)):
            _cv = entry.get(_ck)
            if _cv is not None and (not isinstance(_cv, str) or len(_cv) > _mx):
                raise ValueError(f"tool_calls.{_ck} must be null or a string of <={_mx} chars")
        _rs = entry.get("result_status")
        if _rs is not None and _rs not in ("ok", "error", "denied", "unknown"):
            raise ValueError(f"bad result_status: {_rs!r}")
        _seq = entry.get("seq")
        if _seq is not None and (not isinstance(_seq, int) or isinstance(_seq, bool) or _seq < 0):
            raise ValueError("tool_calls.seq must be null or an int >= 0")

def _validate_mcp_servers(servers) -> None:
    """Mirror the schema's configured_mcp_servers constraints (v1.2).
    Empty list is valid (explicit 'no servers configured')."""
    if not isinstance(servers, list):
        raise ValueError("configured_mcp_servers must be a list")
    if len(servers) > 200:
        raise ValueError("configured_mcp_servers is capped at 200 entries")
    for s in servers:
        if not isinstance(s, dict):
            raise ValueError("configured_mcp_servers entries must be objects")
        extra = set(s) - _MCP_SERVER_KEYS
        if extra:
            raise ValueError(
                f"configured_mcp_servers entry out-of-schema fields: {sorted(extra)}")
        name = s.get("name")
        if not isinstance(name, str) or not (1 <= len(name) <= 128):
            raise ValueError("configured_mcp_servers.name must be a string of 1..128 chars")
        if s.get("scope") not in _MCP_SCOPES:
            raise ValueError(f"bad scope: {s.get('scope')!r}")

