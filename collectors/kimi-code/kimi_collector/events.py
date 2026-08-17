"""Canonical event construction, conforming to the ratified schema:
packages/schema/schema/v1/ai-usage-event.schema.json.

Content policy (locked): no prompt text, conversation content, or
file contents on an event. Kimi Code session data (state.json, wire.jsonl)
contains all of these; wire.jsonl is parsed locally for token/model metadata
and match-flag scanning, and only metadata ever leaves the endpoint. Ingest
rejects out-of-schema fields whole, so everything emitted here must validate
against the schema.

Differences vs the Kilo Code collector (same schema):
- tool = "kimi_code"; provider comes from the wire log's own ``provider``
  field when present (Kimi Code records it per request), falling back to
  model-name prefix derivation.
- cost_estimate_usd is NOT sent: the Kimi Code wire log has no
  provider-reported cost, and a local price table would drift.
- session_id: Kimi session ids are long-lived (a session can span days), so
  per the schema's session_id rule they are re-hashed per UTC day.

Schema v1.1/v1.2 (landed, additive): `event_type` ("usage" | "tool_use" |
"inventory"), `tool_calls` aggregates (mirroring the Claude Code
collector's) — tool names, MCP server ids, action classes, counts,
durations; NEVER arguments, file paths, command lines, or tool output — and
`configured_mcp_servers` inventory entries (names + scope only; NEVER
commands, args, URLs, or env values).
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

SCHEMA_VERSION = "1.10" # v1.10: chain + agent_handoffs
TOOL_NAME = "kimi_code"

# tool_calls entry contract (schema v1.1)
ACTION_CLASSES = ("fs_read", "fs_write", "shell", "network", "mcp_call", "other")
_TOOL_CALL_KEYS = {"tool_name", "mcp_server", "action_class", "count", "duration_ms", "call_id", "parent_call_id", "result_status", "seq"} # chain fields / schema v1.10
_TOOL_CALL_KEYS = {"tool_name", "mcp_server", "action_class", "count", "duration_ms", "call_id", "parent_call_id", "result_status", "seq"}

# configured_mcp_servers entry contract (schema v1.2)
_MCP_SERVER_KEYS = {"name", "scope"}
_MCP_SCOPES = ("user", "project")

# Category/severity mapping derived from detector name prefixes (matchers.py)
_CATEGORY = {"secret": "high", "pii": "medium", "injection": "medium", "policy": "low"}

# Model-name prefix -> provider, for records where the wire log carries no
# explicit provider. Kimi Code is Moonshot AI's CLI and its own wire log
# reports provider "kimi", so we emit "kimi" (not "moonshot") to stay
# consistent with the tool's self-reporting. Kept after the generic prefixes
# so a routed foreign model (e.g. openrouter/anthropic/...) still wins.
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
    ("moonshot", "kimi"),
    ("kimi", "kimi"),
    ("k2", "kimi"),
    ("k3", "kimi"),
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


def daily_session_id(raw_session_id: str, epoch_ms: int | float | None) -> str:
    """Schema rule: re-hash stable/long-lived tool session ids per UTC day
    (HMAC(utc-date || raw_id)) so events cannot be profiled across days."""
    dt = (
        datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
        if epoch_ms is not None
        else datetime.now(timezone.utc)
    )
    return _hmac64(dt.strftime("%Y-%m-%d") + "|" + raw_session_id)


def opaque_call_id(raw_id: str, epoch_ms: int | float | None = None) -> str:
    """Daily-stable opaque call id from a framework toolCallId."""
    return daily_session_id(f"call|{raw_id}", epoch_ms)[:32]


def derive_provider(model: str | None) -> str | None:
    if not model:
        return None
    name = model.strip().lower()
    # strip common router prefixes ("openrouter/anthropic/claude-...", "kimi-code/k3")
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
    provider: str | None = None,
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
        "provider": provider or derive_provider(model),
        "session_id": session_id[:128],
        "repo_ref": repo_ref(workspace_path),
        "match_flags": make_flags(flags or []),
        "source": "endpoint",
    }
    if tokens_in is not None:
        ev["tokens_in"] = int(tokens_in)
    if tokens_out is not None:
        ev["tokens_out"] = int(tokens_out)
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
    tool_calls: list[dict],
    ts_epoch_ms: int | float | None = None,
    workspace_path: str | None = None,
    provider: str | None = None,
    tool_version: str | None = None,
    agent_handoffs: list[dict] | None = None,
) -> dict:
    """event_type='tool_use' (schema v1.1/v1.10/627): per-session
    tool-call aggregates or discrete call_id rows for one scan window. Same
    pseudonymization as new_event (the caller passes the daily-rehashed
    session id). Metadata-only: entries carry tool name, MCP server id,
    action class, count, duration, optional chain fields — never arguments,
    file paths, command lines, or tool output (enforced by _check_tool_calls).
    agent_handoffs is metadata-only."""
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
        "provider": provider or derive_provider(model),
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


_AGENT_HANDOFF_KEYS = {
    "handoff_kind", "status", "child_session_id", "tool_name", "parent_call_id",
}
_HANDOFF_KINDS = ("subagent", "task", "delegate", "other")
_HANDOFF_STATUSES = ("started", "completed", "failed", "cancelled")


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
    """event_type='inventory' (schema v1.2): the MCP servers present
    in the tool's config, emitted only when the set changes. model/provider
    are null and tokens are omitted — this is not LLM traffic. The session
    id is synthetic (``inv_<utc-date>_<host_ref[:12]>``): there is no tool
    session behind a config observation. Entries carry name + scope only —
    never commands, args, URLs, or env values (enforced by
    _check_mcp_servers)."""
    _check_mcp_servers(configured_mcp_servers)
    host = host_ref()
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": format_ts(None),
        "host_ref": host,
        "user_ref": None, # populated by identity-sync; null on the endpoint path
        "tool": TOOL_NAME,
        "tool_version": (tool_version or "")[:64] or None,
        "model": None,
        "provider": None,
        "session_id": f"inv_{day}_{host[:12]}",
        "event_type": "inventory",
        "configured_mcp_servers": configured_mcp_servers,
        "match_flags": [],
        "source": "endpoint",
    }
    for k in ("tool_version",):
        if ev[k] is None:
            del ev[k]
    validate(ev)
    return ev


def _check_tool_calls(tool_calls: list) -> None:
    """Local guard for tool_calls entries (schema v1.1). Rejects anything
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
    Rejects anything beyond name/scope loudly, so config detail (commands,
    args, URLs, env values — env may hold secrets) can never ride on an
    event. An empty list is valid: an explicit 'no servers configured'
    statement."""
    if not isinstance(servers, list):
        raise ValueError("configured_mcp_servers must be a list")
    if len(servers) > 200:
        raise ValueError("configured_mcp_servers is capped at 200 entries")
    for srv in servers:
        if not isinstance(srv, dict):
            raise ValueError("configured_mcp_servers entries must be objects")
        extra = set(srv) - _MCP_SERVER_KEYS
        if extra:
            raise ValueError(
                f"configured_mcp_servers entry has out-of-schema keys: {sorted(extra)}")
        if not isinstance(srv.get("name"), str) or not (1 <= len(srv["name"]) <= 128):
            raise ValueError("name must be a string of 1..128 chars")
        if srv.get("scope") not in _MCP_SCOPES:
            raise ValueError(f"bad scope: {srv.get('scope')!r}")


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
               "repo_ref", "match_flags", "source", "event_type", "tool_calls",
               "configured_mcp_servers", "agent_handoffs"}
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
    if "agent_handoffs" in event:
        _check_agent_handoffs(event["agent_handoffs"])
    if "configured_mcp_servers" in event:
        _check_mcp_servers(event["configured_mcp_servers"])
    if et == "inventory" and "configured_mcp_servers" not in event:
        raise ValueError("event_type='inventory' requires configured_mcp_servers")
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
