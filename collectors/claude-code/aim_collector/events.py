"""Canonical event construction, conforming to the ratified schema:
packages/schema/schema/v1/ai-usage-event.schema.json.

Content policy (locked): no prompt text, tool input/output, file
contents, or code on an event. Ingest rejects out-of-schema fields whole,
so everything emitted here must validate against the schema.

Schema v1.1 (landed, additive): `event_type` ("usage" | "tool_use") and
`tool_calls` aggregates — tool names, MCP server ids, action
classes, counts, durations; NEVER arguments, file paths, command lines,
or tool output.

Schema v1.2: `event_type="inventory"` with
`configured_mcp_servers[]` — MCP server name + scope only, never commands,
args, URLs, or env values. Emitted only when the configured set changes.

Known schema gaps (raised):
- no cache-token split (folded: cache_read counts as input)
- cost is computed platform-side from the price table, NOT sent by collectors
"""

import hashlib
import hmac
import json
import os
import platform
import unicodedata
import uuid
from datetime import datetime, timezone

SCHEMA_VERSION = "1.10" # chain + handoff fields
SCHEMA_VERSION = "1.2"
TOOL_NAME = "claude_code"
PROVIDER = "anthropic"

# tool_calls entry contract (schema v1.1)
ACTION_CLASSES = ("fs_read", "fs_write", "shell", "network", "mcp_call", "other")
_TOOL_CALL_KEYS = {
    "tool_name", "mcp_server", "action_class", "count", "duration_ms",
    "call_id", "parent_call_id", "result_status", "seq", # chain fields
}
# configured_mcp_servers entry contract (schema v1.2)
_MCP_SERVER_KEYS = {"name", "scope"}
_MCP_SCOPES = ("user", "project")

# Category/severity mapping derived from detector name prefixes (matchers.py)
_CATEGORY = {"secret": "high", "pii": "medium", "injection": "medium", "policy": "low"}


def _now_iso() -> str:
    # RFC 3339 with Z suffix (schema format: date-time)
    # schema ts pattern is second-precision: no fractional seconds
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _coerce_iso(ts: str) -> str | None:
    """Normalize an arbitrary RFC3339 string to second-precision Z form, or
    None if unparseable. Lets personal mode date events by the real
    transcript activity time instead of emission time."""
    if not isinstance(ts, str):
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


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
    """HMAC of normalized repo identity. We use the cwd path (normalized)
    as a stand-in for the normalized repo URL until git-remote resolution
    lands; both are pseudonymized identically."""
    if not cwd:
        return None
    norm = os.path.normpath(cwd).lower().replace("\\", "/")
    return _hmac64(norm)


def session_id(raw_id: str, day: str | None = None) -> str:
    """Re-hash a stable/long-lived tool session id per UTC day, as the
    schema requires: HMAC(utc-date || raw_id). Claude Code session ids are
    long-lived (a resumed session keeps its id across days), so passing them
    through verbatim would let events be profiled across days. `day` is
    injectable for tests; default is the current UTC date. Mirrors the
    cursor collector."""
    if day is None:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return _hmac64(f"{day}|{raw_id}")


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


ENFORCEMENT_ACTIONS = ("blocked", "would_block", "confirmed", "redacted")


def check_enforcement(rec: dict) -> None:
    """Local guard for the enforcement audit record (schema v1.5;
    v1.6 added 'confirmed' PII confirm-prompt and
    secret break-glass override; v1.9 added 'redacted' for the
    secret break-glass override; v1.10 added 'redacted' for the
    inline-redaction guardrail; v1.11 added optional multi-rail
    attribution via ``rails``).
    Rejects anything beyond action/rule_id/policy_hash/rails loudly, so the
    blocked payload or the user-visible reason string can never ride on an
    event."""
    allowed = {"action", "rule_id", "policy_hash", "rails"}
    extra = set(rec) - allowed
    if extra:
        raise ValueError(f"enforcement record has out-of-schema keys: {sorted(extra)}")
    if rec.get("action") not in ENFORCEMENT_ACTIONS:
        raise ValueError(f"bad enforcement action: {rec.get('action')!r}")
    rid = rec.get("rule_id")
    if not isinstance(rid, str) or not (1 <= len(rid) <= 64):
        raise ValueError("enforcement rule_id must be a string of 1..64 chars")
    ph = rec.get("policy_hash")
    if ph is not None and (not isinstance(ph, str) or len(ph) > 64):
        raise ValueError("enforcement policy_hash must be a string of <=64 chars or null")
    if ph is None:
        rec.pop("policy_hash", None)
    rails = rec.get("rails")
    if rails is not None:
        if not isinstance(rails, list) or not (2 <= len(rails) <= 8):
            raise ValueError("enforcement rails must be a list of 2..8 entries when present")
        for i, entry in enumerate(rails):
            if not isinstance(entry, dict):
                raise ValueError(f"enforcement rails[{i}] must be an object")
            ekeys = set(entry) - {"rule_id", "action"}
            if ekeys:
                raise ValueError(f"enforcement rails[{i}] has out-of-schema keys: {sorted(ekeys)}")
            erid = entry.get("rule_id")
            if not isinstance(erid, str) or not (1 <= len(erid) <= 64):
                raise ValueError(f"enforcement rails[{i}].rule_id must be a string of 1..64 chars")
            if entry.get("action") not in ENFORCEMENT_ACTIONS:
                raise ValueError(f"enforcement rails[{i}].action bad: {entry.get('action')!r}")
        if rails[0].get("rule_id") != rid:
            raise ValueError("enforcement rails[0].rule_id must match enforcement.rule_id")
        if rails[0].get("action") != rec.get("action"):
            raise ValueError("enforcement rails[0].action must match enforcement.action")


def check_enforcement_posture(rec: dict) -> None:
    """Local guard for the enforcement coverage marker (schema v1.7).
    Posture is the bake's denominator, so a malformed one is worse than none:
    it would be counted as coverage the fleet does not actually have.

    (v1.10): optional ``enforcement_latency_ms`` is decision-path
    wall time only — integer ms, never content.

    (v1.11): optional ``cohort_member`` bool reports canary membership
    when a cohort is configured — config metadata only, never a host id.
    """
    allowed = {
        "policy",
        "mode",
        "evaluated",
        "policy_hash",
        "enforcement_latency_ms",
        "cohort_member",
    }
    extra = set(rec) - allowed
    if extra:
        raise ValueError(f"enforcement_posture has out-of-schema keys: {sorted(extra)}")
    if rec.get("policy") not in ("absent", "loaded"):
        raise ValueError(f"bad enforcement_posture policy: {rec.get('policy')!r}")
    if not isinstance(rec.get("evaluated"), bool):
        raise ValueError("enforcement_posture evaluated must be a bool")
    mode = rec.get("mode")
    if mode is not None and mode not in ("shadow", "enforce"):
        raise ValueError(f"bad enforcement_posture mode: {mode!r}")
    if rec.get("policy") == "absent" and mode is not None:
        raise ValueError("enforcement_posture mode is meaningless without a loaded policy")
    ph = rec.get("policy_hash")
    if ph is not None and (not isinstance(ph, str) or len(ph) > 64):
        raise ValueError("enforcement_posture policy_hash must be a string of <=64 chars or null")
    if ph is None:
        rec.pop("policy_hash", None)
    lat = rec.get("enforcement_latency_ms")
    if lat is not None:
        if not isinstance(lat, int) or isinstance(lat, bool) or lat < 0 or lat > 60000:
            raise ValueError(
                f"enforcement_posture enforcement_latency_ms must be int 0..60000, got {lat!r}"
            )
    cm = rec.get("cohort_member")
    if cm is not None and not isinstance(cm, bool):
        raise ValueError(
            f"enforcement_posture cohort_member must be a bool, got {cm!r}"
        )
    if rec.get("policy") == "absent" and cm is not None:
        raise ValueError(
            "enforcement_posture cohort_member is meaningless without a loaded policy"
        )


def new_event(
    *,
    raw_session_id: str,
    model: str | None,
    cwd: str | None = None,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    flags: list[str] | None = None,
    tool_version: str | None = None,
    ts: str | None = None,
    enforcement: dict | None = None,
    enforcement_posture: dict | None = None,
) -> dict:
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        # ts defaults to emission time (network path); personal mode passes the
        # transcript activity time so historical usage lands on its real day.
        "ts": (ts and _coerce_iso(ts)) or _now_iso(),
        "host_ref": host_ref(),
        "user_ref": None, # populated by identity-sync; null on the endpoint path
        "tool": TOOL_NAME,
        "tool_version": (tool_version or "")[:64] or None,
        "model": model,
        "provider": PROVIDER if model else None,
        "session_id": session_id(raw_session_id),
        "repo_ref": repo_ref(cwd),
        "match_flags": make_flags(flags or []),
        "source": "endpoint",
    }
    if tokens_in is not None:
        ev["tokens_in"] = int(tokens_in)
    if tokens_out is not None:
        ev["tokens_out"] = int(tokens_out)
    if enforcement is not None:
        ev["enforcement"] = dict(enforcement)
    if enforcement_posture is not None:
        ev["enforcement_posture"] = dict(enforcement_posture)
    # strip None optionals the schema doesn't type as nullable
    for k in ("tool_version",):
        if ev[k] is None:
            del ev[k]
    validate(ev)
    return ev


def new_tool_use_event(
    *,
    raw_session_id: str,
    model: str | None,
    cwd: str | None = None,
    tool_calls: list[dict],
    tool_version: str | None = None,
    ts: str | None = None,
    agent_handoffs: list[dict] | None = None,
) -> dict:
    """event_type='tool_use' (schema v1.1; chain/handoffs v1.10).

    Per-session tool-call aggregates or discrete call_id rows for one flush
    window. Metadata-only: names, classes, counts, durations, opaque chain
    ids, coarse result_status — never arguments, file paths, command lines,
    or tool output (enforced by _check_tool_calls).
    """
    _check_tool_calls(tool_calls)
    if agent_handoffs:
        _check_agent_handoffs(agent_handoffs)
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": (ts and _coerce_iso(ts)) or _now_iso(),
        "host_ref": host_ref(),
        "user_ref": None, # populated by identity-sync; null on the endpoint path
        "tool": TOOL_NAME,
        "tool_version": (tool_version or "")[:64] or None,
        "model": model,
        "provider": PROVIDER if model else None,
        "session_id": session_id(raw_session_id),
        "repo_ref": repo_ref(cwd),
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
    """event_type='inventory' (schema v1.2): MCP servers
    present in Claude Code config files. Emitted only when the configured
    set changes (change detection lives in mcp_inventory). No model/
    provider/tokens — this is not LLM traffic. Metadata-only: server name
    + scope, never commands, args, URLs, or env values."""
    _check_mcp_servers(configured_mcp_servers)
    host = host_ref()
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": _now_iso(),
        "host_ref": host,
        "user_ref": None, # populated by identity-sync; null on the endpoint path
        "tool": TOOL_NAME,
        "tool_version": (tool_version or "")[:64] or None,
        "model": None,
        "provider": None,
        # synthetic session: no tool session exists for config inventory
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
    Empty list is valid (explicit 'no servers configured'); anything beyond
    name/scope is rejected so commands, args, URLs, or env values can never
    ride on an event."""
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
               "repo_ref", "match_flags", "source", "event_type", "tool_calls",
               "enforcement", "enforcement_posture", "agent_handoffs",
               "configured_mcp_servers"}
    extra = set(event) - allowed
    if extra:
        raise ValueError(f"out-of-schema fields (ingest would reject): {sorted(extra)}")
    if "enforcement" in event:
        check_enforcement(event["enforcement"])
    if "enforcement_posture" in event:
        check_enforcement_posture(event["enforcement_posture"])
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
    import re
    if not re.fullmatch(r"1\.[0-9]+", event["schema_version"]):
        raise ValueError("bad schema_version")
    for k in ("host_ref", "repo_ref"):
        v = event.get(k)
        if v is not None and not re.fullmatch(r"[0-9a-f]{64}", str(v)):
            raise ValueError(f"{k} must be 64 lowercase hex chars")
    json.dumps(event)  # must be serializable
