"""Canonical event construction, conforming to the ratified schema:
packages/schema/schema/v1/ai-usage-event.schema.json.

Content policy (locked): no prompt text, conversation content, or
file contents on an event. Kilo Code task logs contain all of these; they
are read locally for token/cost metadata and match-flag scanning, and only
metadata ever leaves the endpoint. Ingest rejects out-of-schema fields
whole, so everything emitted here must validate against the schema.

Differences vs the Claude Code collector (same schema):
- tool = "kilo_code"; provider is derived from the model name (Kilo Code is
  provider-agnostic: OpenRouter, Bedrock, direct APIs, ...)
- cost_estimate_usd IS sent when Kilo Code reports it: unlike Claude Code
  (platform price table), Kilo records the provider-reported cost per API
  request, which a static price table cannot reproduce across providers.
- session_id: Kilo task ids are long-lived (a task can span days), so per
  the schema's session_id rule they are re-hashed per UTC day.

Schema v1.1/v1.2 (landed, additive): `event_type` ("usage" | "tool_use" |
"inventory"), `tool_calls` aggregates (pattern) and
`configured_mcp_servers` inventory — tool/server names, action
classes, counts; NEVER arguments, file paths, command lines, URLs, env
values, or tool output.

Schema v1.10: optional chain fields on tool_calls[] (`call_id`,
`parent_call_id`, `result_status`, `seq`) and event-level `agent_handoffs[]`
for Task/subagent spawn tools. Metadata only — never args or result bodies.
"""

import hashlib
import hmac
import json
import os
import platform
import unicodedata
import re
import uuid
from datetime import datetime, timezone

SCHEMA_VERSION = "1.10" # chain fields + agent_handoffs (was 1.2)
TOOL_NAME = "kilo_code"

# tool_calls entry contract (schema v1.1+,; chain v1.10)
ACTION_CLASSES = ("fs_read", "fs_write", "shell", "network", "mcp_call", "other")
_TOOL_CALL_KEYS = {"tool_name", "mcp_server", "action_class", "count", "duration_ms", "call_id", "parent_call_id", "result_status", "seq"}
# configured_mcp_servers entry contract (schema v1.2)
_MCP_SERVER_KEYS = {"name", "scope"}
_MCP_SCOPES = ("user", "project")

# A2A handoff tools (Kilo/Roo/Cline lineage names, lowercased).
_AGENT_HANDOFF_KEYS = {
    "handoff_kind", "status", "child_session_id", "tool_name", "parent_call_id",
}
_HANDOFF_KINDS = ("subagent", "task", "delegate", "other")
_HANDOFF_STATUSES = ("started", "completed", "failed", "cancelled")
_HANDOFF_TOOL_KIND = {
    "newtask": "task",
    "task": "task",
    "taskv2": "task",
    "agent": "subagent",
    "new_agent": "subagent",
}

# Category/severity mapping derived from detector name prefixes (matchers.py)
_CATEGORY = {"secret": "high", "pii": "medium", "injection": "medium", "policy": "low"}

_MODEL_PROVIDER_PREFIXES = (
    ("claude", "anthropic"),
    ("gpt", "openai"),
    ("o1", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
    ("gemini", "google"),
    ("grok", "xai"),
    ("deepseek", "deepseek"),
    ("qwen", "alibaba"),
    ("mistral", "mistral"),
    ("llama", "meta"),
)


def _now_iso() -> str:
    return format_ts(None)


def format_ts(epoch_ms: int | float | None) -> str:
    """RFC 3339 UTC, second precision, Z suffix (schema ts pattern)."""
    dt = (
        datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
        if epoch_ms is not None
        else datetime.now(timezone.utc)
    )
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def _salt() -> bytes:
    """HMAC salt for pseudonymization. Same resolution as the Claude Code
    collector: AIM_HASH_SALT env > managed config `hash_salt` > per-install
    random salt in the state dir (dev/pilot deviation)."""
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


def repo_ref(workspace_path: str | None) -> str | None:
    """HMAC of the normalized workspace path (stand-in for normalized repo
    URL until git-remote resolution lands; pseudonymized identically)."""
    if not workspace_path:
        return None
    norm = os.path.normpath(workspace_path).lower().replace("\\", "/")
    return _hmac64(norm)


def daily_session_id(raw_task_id: str, epoch_ms: int | float | None) -> str:
    """Schema rule: re-hash stable/long-lived tool session ids per UTC day
    (HMAC(utc-date || raw_id)) so events cannot be profiled across days."""
    dt = (
        datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
        if epoch_ms is not None
        else datetime.now(timezone.utc)
    )
    return _hmac64(dt.strftime("%Y-%m-%d") + "|" + raw_task_id)


def opaque_call_id(raw_tool_id: str) -> str:
    """Daily-stable opaque call_id from a synthetic aggregate key.
    Never put raw framework ids on the wire."""
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return _hmac64(day + "|call|" + raw_tool_id)[:64]


def handoff_kind_for(tool_name: str) -> str | None:
    """Return handoff_kind if tool_name is a Task/Agent spawn (name only)."""
    if not tool_name:
        return None
    key = tool_name.strip().lower().replace("_", "").replace("-", "")
    # also try raw lower
    return _HANDOFF_TOOL_KIND.get(key) or _HANDOFF_TOOL_KIND.get(tool_name.strip().lower())


def derive_provider(model: str | None) -> str | None:
    if not model:
        return None
    name = model.strip().lower()
    # strip common router prefixes ("openrouter/anthropic/claude-...", "anthropic/claude-...")
    name = name.split("/")[-1]
    for prefix, provider in _MODEL_PROVIDER_PREFIXES:
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


def new_event(
    *,
    session_id: str,
    model: str | None,
    ts_epoch_ms: int | float | None = None,
    workspace_path: str | None = None,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    cost_usd: float | None = None,
    flags: list[str] | None = None,
    tool_version: str | None = None,
) -> dict:
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": format_ts(ts_epoch_ms),
        "host_ref": host_ref(),
        "user_ref": None, # populated by identity-sync; null on the endpoint path
        "tool": TOOL_NAME,
        "tool_version": (tool_version or "")[:64] or None,
        "model": (model or "")[:128] or None,
        "provider": derive_provider(model),
        "session_id": session_id[:128],
        "repo_ref": repo_ref(workspace_path),
        "match_flags": make_flags(flags or []),
        "source": "endpoint",
    }
    if tokens_in is not None:
        ev["tokens_in"] = int(tokens_in)
    if tokens_out is not None:
        ev["tokens_out"] = int(tokens_out)
    if cost_usd is not None:
        ev["cost_estimate_usd"] = round(float(cost_usd), 6)
    # strip None optionals the schema doesn't type as nullable
    for k in ("tool_version",):
        if ev[k] is None:
            del ev[k]
    validate(ev)
    return ev


def new_tool_use_event(
    *,
    session_id: str,
    model: str | None,
    ts_epoch_ms: int | float | None = None,
    workspace_path: str | None = None,
    tool_calls: list[dict],
    tool_version: str | None = None,
    agent_handoffs: list[dict] | None = None,
) -> dict:
    """event_type='tool_use' (schema v1.10):
    per-task tool-call aggregates for one scan window. Same pseudonymization
    as new_event (caller passes the daily-hashed session_id). Metadata-only:
    entries carry tool name, MCP server id, action class, count, duration,
    optional chain fields — never arguments, file paths, command lines, or
    tool output (enforced by _check_tool_calls). agent_handoffs is optional
    Task/subagent linkage metadata."""
    _check_tool_calls(tool_calls)
    if agent_handoffs:
        _check_agent_handoffs(agent_handoffs)
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": format_ts(ts_epoch_ms),
        "host_ref": host_ref(),
        "user_ref": None, # populated by identity-sync; null on the endpoint path
        "tool": TOOL_NAME,
        "tool_version": (tool_version or "")[:64] or None,
        "model": (model or "")[:128] or None,
        "provider": derive_provider(model),
        "session_id": session_id[:128],
        "repo_ref": repo_ref(workspace_path),
        "event_type": "tool_use",
        "tool_calls": tool_calls,
        "match_flags": [],
        "source": "endpoint",
    }
    if agent_handoffs:
        ev["agent_handoffs"] = agent_handoffs
    for k in ("tool_version",):
        if ev[k] is None:
            del ev[k]
    validate(ev)
    return ev


def _check_agent_handoffs(handoffs: list) -> None:
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
    """event_type='inventory' (schema v1.2): MCP servers present in
    Kilo Code's config files. Emitted only when the configured set changes
    (change detection lives in mcp_inventory). No model/provider/tokens —
    this is not LLM traffic. Metadata-only: server name + scope, never
    commands, args, URLs, or env values (enforced by _check_mcp_servers)."""
    _check_mcp_servers(configured_mcp_servers)
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": _now_iso(),
        "host_ref": host_ref(),
        "user_ref": None, # populated by identity-sync; null on the endpoint path
        "tool": TOOL_NAME,
        "tool_version": (tool_version or "")[:64] or None,
        "model": None,
        "provider": None,
        # synthetic session: no tool session exists for config inventory
        "session_id": f"inv_{day}_{host_ref()[:12]}",
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


def _check_tool_calls(tool_calls: list) -> None:
    """Local guard for tool_calls entries (schema v1.1+). Rejects anything
    beyond name/server/class/count/duration loudly, so arguments or output
    can never ride on an event."""
    if not isinstance(tool_calls, list) or not tool_calls:
        raise ValueError("tool_calls must be a non-empty list")
    for tc in tool_calls:
        if not isinstance(tc, dict):
            raise ValueError("tool_calls entries must be objects")
        extra = set(tc) - _TOOL_CALL_KEYS
        if extra:
            raise ValueError(f"tool_calls entry has out-of-schema keys: {sorted(extra)}")
        for k in ("tool_name", "action_class", "count"):
            if k not in tc:
                raise ValueError(f"tool_calls entry missing required key: {k}")
        if not isinstance(tc["tool_name"], str) or not (1 <= len(tc["tool_name"]) <= 64):
            raise ValueError("tool_name must be a string of 1..64 chars")
        srv = tc.get("mcp_server")
        if srv is not None and (not isinstance(srv, str) or len(srv) > 128):
            raise ValueError("mcp_server must be a string of <=128 chars or null")
        if tc["action_class"] not in ACTION_CLASSES:
            raise ValueError(f"bad action_class: {tc['action_class']!r}")
        if not isinstance(tc["count"], int) or tc["count"] < 1:
            raise ValueError("count must be an int >= 1")
        dur = tc.get("duration_ms")
        if dur is not None and (not isinstance(dur, int) or dur < 0):
            raise ValueError("duration_ms must be an int >= 0 or null")

        # / schema v1.10 chain metadata (optional; never arguments/results).
        for _ck, _mx in (("call_id", 64), ("parent_call_id", 64)):
            _cv = tc.get(_ck)
            if _cv is not None and (not isinstance(_cv, str) or len(_cv) > _mx):
                raise ValueError(f"tool_calls.{_ck} must be null or a string of <={_mx} chars")
        _rs = tc.get("result_status")
        if _rs is not None and _rs not in ("ok", "error", "denied", "unknown"):
            raise ValueError(f"bad result_status: {_rs!r}")
        _seq = tc.get("seq")
        if _seq is not None and (not isinstance(_seq, int) or isinstance(_seq, bool) or _seq < 0):
            raise ValueError("tool_calls.seq must be null or an int >= 0")


def _check_mcp_servers(servers: list) -> None:
    """Local guard for configured_mcp_servers entries (schema v1.2).
    Empty list is valid (an explicit 'no servers configured' statement);
    anything beyond name/scope is rejected loudly so commands, args, URLs,
    or env values can never ride on an event."""
    if not isinstance(servers, list):
        raise ValueError("configured_mcp_servers must be a list")
    for s in servers:
        if not isinstance(s, dict):
            raise ValueError("configured_mcp_servers entries must be objects")
        extra = set(s) - _MCP_SERVER_KEYS
        if extra:
            raise ValueError(
                f"configured_mcp_servers entry has out-of-schema keys: {sorted(extra)}")
        if not isinstance(s.get("name"), str) or not (1 <= len(s["name"]) <= 128):
            raise ValueError("name must be a string of 1..128 chars")
        if s.get("scope") not in _MCP_SCOPES:
            raise ValueError(f"bad scope: {s.get('scope')!r}")


def validate(event: dict) -> None:
    """Local conformance check against the schema's hard constraints.
    Ingest-side JSON Schema validation remains authoritative."""
    required = ("schema_version", "event_id", "ts", "host_ref", "tool",
                "session_id", "source", "match_flags", "model")
    missing = [k for k in required if k not in event]
    if missing:
        raise ValueError(f"event missing required fields: {missing}")
    allowed = {"schema_version", "event_id", "ts", "host_ref", "user_ref",
               "tool", "tool_raw", "tool_version", "model", "provider",
               "session_id", "tokens_in", "tokens_out", "cost_estimate_usd",
               "repo_ref", "match_flags", "source", "event_type",
               "tool_calls", "configured_mcp_servers", "agent_handoffs"}
    extra = set(event) - allowed
    if extra:
        raise ValueError(f"out-of-schema fields (ingest would reject): {sorted(extra)}")
    et = event.get("event_type")
    if et is not None and et not in ("usage", "tool_use", "inventory"):
        raise ValueError(f"bad event_type: {et!r}")
    if "tool_calls" in event:
        _check_tool_calls(event["tool_calls"])
    if et == "tool_use" and "tool_calls" not in event:
        raise ValueError("event_type='tool_use' requires tool_calls")
    if "configured_mcp_servers" in event:
        _check_mcp_servers(event["configured_mcp_servers"])
    if et == "inventory" and "configured_mcp_servers" not in event:
        raise ValueError("event_type='inventory' requires configured_mcp_servers")
    ahs = event.get("agent_handoffs")
    if ahs is not None:
        _check_agent_handoffs(ahs)
    if not re.fullmatch(r"1\.[0-9]+", event["schema_version"]):
        raise ValueError("bad schema_version")
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})", event["ts"]
    ):
        raise ValueError("ts must be RFC 3339 second precision")
    for k in ("host_ref", "repo_ref"):
        v = event.get(k)
        if v is not None and not re.fullmatch(r"[0-9a-f]{64}", str(v)):
            raise ValueError(f"{k} must be 64 lowercase hex chars")
    if event["tool"] != TOOL_NAME:
        raise ValueError(f"tool must be {TOOL_NAME!r}")
    json.dumps(event)  # must be serializable
