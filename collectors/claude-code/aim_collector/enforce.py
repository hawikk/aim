"""Endpoint inline-enforcement policy & decisions (AIM-110 Phase 1).

AIM-15 amended 2026-07-22 (board-approved): "observe + endpoint blocking for
critical rules". Metadata-only posture is untouched — decisions are computed
locally from matchers that already run on the endpoint, and the only thing
that leaves the machine is the audit record (action + rule id + policy hash,
schema v1.5 `enforcement` field). No content, no blocked payload, no reason
strings cross the wire.

Phase 1 ships exactly two enforceable rules:

  - ``secret-pattern-in-prompt`` (UserPromptSubmit): any ``secret:*`` detector
    firing on the prompt text. Hard block on first submit when enforce is on
    (AIM-296 phase-1 out of shadow). Break-glass: resubmit the identical
    prompt within ``secret_override_ttl_seconds`` to override; the override is
    audited as action ``confirmed`` with ``rule_id`` + ``policy_hash`` (schema
    v1.6). Optional manager gate (AIM-791): when
    ``secret_override_requires_manager`` is true (default **false** — do not
    enable in pilot without CEO/Security sign-off), the first resubmit opens a
    local approval request instead of confirming; only a local operator grant
    (ticket id, no content) allows a later resubmit to confirm. Matched content
    and the user-visible reason never leave the endpoint. PII and injection
    detectors stay observe-only by policy — they are not in scope for endpoint
    hard-blocking.
  - ``unapproved-mcp-server`` (PreToolUse): MCP tool calls (``mcp__<server>__*``)
    to a server outside the approved inventory (from AIM-97). An
    unparseable/unknown server name counts as unapproved, matching the
    guardrail engine's semantics. Stays shadow until the approved inventory
    is populated (AIM-296: only secret-pattern flips).

Phase 2a (AIM-111) ships shadow-first: the rules below are built and evaluated
but stay in shadow until the phase-1 telemetry gate is satisfied and an
operator enables them.

  - ``restricted-repo-access`` (PreToolUse): deny file-touching tool calls
    (Read/Write/Edit/MultiEdit/NotebookEdit/Glob/Grep — anything carrying
    ``file_path``/``path``/``notebook_path``) whose path sits under a
    configured restricted root. Bash free text is out of scope.
  - ``pii-in-prompt`` (UserPromptSubmit): confirm-prompt, NOT a hard block.
    An enforcement-eligible ``pii:*`` detector firing blocks the first
    submission with a challenge reason (AIM-128: a bare email is only eligible
    when it co-occurs with another sensitive signal — see
    ``eligible_pii_flags``); resubmitting the identical prompt within
    ``pii_confirm_ttl_seconds`` is the user's explicit confirmation and is
    allowed through (audited as action ``confirmed``, schema v1.6). The
    confirm state is a local content hash in the state dir — nothing new
    leaves the machine.

Inline redaction (AIM-320 — the "redact, not just block" gap closure):

  - ``secret-in-tool-input`` (PreToolUse): ``secret:*`` detectors firing on
    any string field of ``tool_input``. Per-rule ``action`` selects the
    applied behavior alongside the existing observe (shadow) / block:
    ``"redact"`` rewrites the matched spans to ``[REDACTED:<detector>]``
    markers and lets the tool call proceed with the redacted input — the
    secret never leaves the host and the work continues. Redaction covers
    raw-text spans only; if a detector still fires on the redacted input
    (evasion-encoded content: normalized/squashed/base64-only matches), the
    decision falls back to ``blocked`` — redacted-but-still-secret must never
    egress. The audit event records action ``redacted`` (schema v1.9) +
    ``rule_id`` + ``policy_hash`` + the usual detector match_flags; the
    matched secret itself is stored nowhere (reversible-by-no-one).
    UserPromptSubmit has no rewrite primitive in the hook API, so prompts
    stay block/confirm — redaction is a tool-input action only.

Multi-rail orchestration (AIM-792): when more than one of the rules above
could fire on a single hook invocation, ``decide_user_prompt_submit`` /
``decide_pretool_use`` select exactly one Decision by fixed precedence
(secret-pattern > pii-confirm on prompts; secret-in-tool-input >
unapproved-mcp > restricted-repo on PreToolUse). Hook code must not chain
the per-rail decide_* helpers itself — dual stdout deny+allow and dual
audit actions are the failure mode this closes.

Fail-open is a hard requirement (design: docs/inline-enforcement-design-2026-07.md
§4): any error — missing/malformed policy, matcher exception, audit-event
construction failure — degrades to observe (exit 0, no decision output). We
never break an engineer's tool on our own outage.

Policy delivery: a managed JSON file dropped by endpoint tooling at the same
channel as the collector config (Intune/SCCM on Windows, config-management on
Linux). Search order mirrors config.py:

1. ``AIM_ENFORCEMENT_FILE`` env var (explicit override, used by tests/dev)
2. platform managed path:
   - Windows: ``%ProgramData%\\AI-Monitoring\\collector\\enforcement.json``
   - macOS: ``/Library/Application Support/AI-Monitoring/collector/enforcement.json``
     then ``~/Library/Application Support/AI-Monitoring/collector/enforcement.json``
     then legacy AIM-743 ``/etc/aim-collector/enforcement.json``
   - Linux/WSL: ``/etc/aim-collector/enforcement.json``
3. ``<state dir>/enforcement.json`` (per-user fallback, dev default)

Policy shape::

    {
      "version": 1,
      "policy_hash": "<64-hex tag of the signed ruleset, for audit continuity>",
      "mode": "shadow",                 // "shadow" (default) | "enforce"
      "rules": {
        // AIM-793: optional per-rule cohort canary. Outside the cohort the
        // rule stays shadow even when enforce:true (would_block + local
        // cohort reason). Expand/rollback = percent + policy_hash bump only.
        "secret-pattern-in-prompt": {
          "enforce": true,
          "cohort": {"percent": 5, "salt": "secret-canary-2026-08"}
        },
        "unapproved-mcp-server":    {"enforce": false},
        "secret-pattern-in-prompt": {"enforce": true},   // AIM-296: phase-1 flip
        "unapproved-mcp-server":    {"enforce": true},   // AIM-547 pilot
        "restricted-repo-access":   {"enforce": false},  // fleet; pilot overlay AIM-566

        "pii-in-prompt":            {"enforce": false},
        "secret-in-tool-input":     {"enforce": false,   // AIM-320
                                     "action": "redact"} // "block" (default) | "redact"
      },
      // Optional top-level cohort fallback when a rule has enforce:true but
      // no per-rule cohort block (same shape as the per-rule object).
      "cohort": {"percent": 100, "salt": "fleet-default"},
      "approved_mcp_servers": ["github", "filesystem"],
      "approved_mcp_servers": ["ide", "claude_ai_Gmail", "claude_ai_Google_Calendar"],
      "restricted_repo_paths": ["/srv/corp-secrets"],
      "pii_confirm_ttl_seconds": 120,
      "secret_override_ttl_seconds": 120,
      "restricted_repo_override_ttl_seconds": 120,
      "redact_prefixes": ["secret:"]   // detector prefixes redaction may rewrite
      "redact_prefixes": ["secret:"],  // detector prefixes redaction may rewrite
      "secret_override_requires_manager": false,
      "secret_override_manager_grant_ttl_seconds": 3600
    }

Semantics: a decision is *applied* only when the global ``mode`` is
``"enforce"`` AND the rule's per-rule ``enforce`` flag is true AND the host
is inside the rule's cohort (when a cohort is configured) — the global mode
is the fleet-wide kill switch / bake control, the per-rule flag is
Security's toggle after the gates (works-council consultation, ruleset
sign-off) clear, and the cohort is the canary dial (AIM-793). In every other
state a firing rule yields ``would_block`` (shadow): the decision is logged
as an audit event but nothing is interrupted. A missing policy file means
full observe: not even shadow decisions are computed, so a fleet without a
delivered bundle behaves exactly as before AIM-110.
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import NamedTuple

from . import matchers, state

MANAGED_PATH_WINDOWS = r"C:\ProgramData\AI-Monitoring\collector\enforcement.json"
MANAGED_PATH_LINUX = "/etc/aim-collector/enforcement.json"
MANAGED_PATH_DARWIN = "/Library/Application Support/AI-Monitoring/collector/enforcement.json"
MANAGED_PATH_DARWIN_USER = "~/Library/Application Support/AI-Monitoring/collector/enforcement.json"

RULE_SECRET_IN_PROMPT = "secret-pattern-in-prompt"
RULE_UNAPPROVED_MCP = "unapproved-mcp-server"
# AIM-111 Phase 2a (shadow-first; gated on phase-1 telemetry before enablement):
RULE_RESTRICTED_REPO = "restricted-repo-access"
RULE_PII_IN_PROMPT = "pii-in-prompt"
# AIM-320 inline redaction (shadow-first, same enablement gates as 2a):
RULE_SECRET_IN_TOOL_INPUT = "secret-in-tool-input"
ENFORCEABLE_RULES = (RULE_SECRET_IN_PROMPT, RULE_UNAPPROVED_MCP,
                     RULE_RESTRICTED_REPO, RULE_PII_IN_PROMPT,
                     RULE_SECRET_IN_TOOL_INPUT)

# Per-rule applied actions. "block" is the default and the fail-safe: any
# missing/unknown action value means block. "redact" is honored only by rules
# whose surface is rewritable (PreToolUse tool_input, AIM-320) — the hook API
# has no prompt-rewrite primitive, so a prompt rule configured "redact" still
# blocks (a secret must never egress on a config mistake).
ACTION_BLOCK = "block"
ACTION_REDACT = "redact"

# PreToolUse tool_input keys that carry a filesystem path worth checking
# against the restricted-repo list. Bash free-text commands are out of scope
# (parsing shell is a false-positive farm; the server-side
# shell-tool-restricted-repo rule covers the observe path).
_PATH_INPUT_KEYS = ("file_path", "path", "notebook_path")

# How long a PII confirm challenge stays valid. Resubmitting the identical
# prompt within the window is the user's explicit confirmation.
PII_CONFIRM_TTL_DEFAULT = 120
PII_CONFIRM_TTL_MAX = 3600

# AIM-296: secret break-glass window. Same shape as PII confirm — resubmit the
# identical prompt within the TTL to override a hard block. Default matches
# pii so the UX is one pattern; Security can retune without a collector release.
SECRET_OVERRIDE_TTL_DEFAULT = 120
# AIM-627: MCP unapproved-server break-glass (resubmit same tool within TTL).
MCP_OVERRIDE_TTL_DEFAULT = 120
MCP_OVERRIDE_TTL_MAX = 3600
SECRET_OVERRIDE_TTL_MAX = 3600
# AIM-566: restricted-repo-access break-glass (resubmit same tool+path).
RESTRICTED_REPO_OVERRIDE_TTL_DEFAULT = 120
RESTRICTED_REPO_OVERRIDE_TTL_MAX = 3600

# AIM-784: when true, local resubmit is not enough — an approved, unexpired
# grant must be present in the endpoint grants file (synced from the control
# plane). Default false so pilot break-glass stays one-step. CEO/Security
# must sign off before enabling fleet-wide.
SECRET_OVERRIDE_REQUIRES_MANAGER_DEFAULT = False
# AIM-791: manager-approval extension for secret break-glass. Default OFF —
# pilot stays one-step resubmit. When Security/CEO flip
# ``secret_override_requires_manager: true``, a challenge resubmit opens a
# local pending request and only confirms after an operator grant (ticket id
# field, no prompt content). Grant TTL is independent so a manager can act
# after the short challenge window.
SECRET_OVERRIDE_REQUIRES_MANAGER_DEFAULT = False
SECRET_OVERRIDE_MANAGER_GRANT_TTL_DEFAULT = 3600
SECRET_OVERRIDE_MANAGER_GRANT_TTL_MAX = 86_400

# AIM-128: pii:email is the dominant false-positive source in a coding context.
# The AIM-117 dogfood backtest fired pii-in-prompt on 251 prompts (~22% of all
# prompts) and every one was a bare email address in normal engineering content
# (git authorship, harness/agent addresses, doc examples, test fixtures) — zero
# were third-party personal data being exfiltrated, and 250 of the 251 carried
# no other sensitive signal. Email is therefore treated as LOW sensitivity: it
# is only enforcement-eligible for pii-in-prompt when it co-occurs with another
# sensitive class (a checksum-validated structured PII detector, or a secret).
# The structured PII detectors (SSN / credit-card / IBAN / national IDs) are
# high precision and genuinely sensitive, so they stay eligible on their own.
# Configurable via policy (pii_low_sensitivity_detectors) so Security can retune
# without a collector release; an empty list restores pre-AIM-128 behavior.
PII_LOW_SENSITIVITY_DEFAULT = ("pii:email",)


class Decision(NamedTuple):
    rule_id: str
    action: str  # "blocked" (applied) | "would_block" (shadow) | "confirmed" (PII resubmit)
                 # | "redacted" (applied, AIM-320: spans rewritten, call proceeded)
    reason: str  # user-visible; NEVER leaves the endpoint
    hook_event: str  # "UserPromptSubmit" | "PreToolUse"
    updated_input: dict | None = None  # AIM-320: redacted tool_input for PreToolUse


class OrchestratedDecision(NamedTuple):
    """Single actuation with multi-rail attribution (AIM-782).

    ``decision`` is the primary rail that drives the hook deny/block output
    (exactly one actuation per hook invocation). ``rails`` lists every rail
    that fired on this invocation, ordered by deterministic precedence —
    ``rails[0]`` is always the primary. Single-rail invocations have
    ``len(rails) == 1``; dual-rail events emit attribution on the audit
    record without a second block/deny.
    """
    decision: Decision
    rails: tuple  # tuple[Decision, ...]; non-empty, rails[0] is decision


# ---------------------------------------------------------------------------
# AIM-782 multi-rail precedence (Decision C rails + held PII observe path)
# ---------------------------------------------------------------------------
# Higher rank wins. Documented in docs/security/multi-rail-precedence.md.
# UserPromptSubmit and PreToolUse never share an invocation, so cross-hook
# dual-actuation is impossible by construction.
RAIL_PRECEDENCE = {
    # UserPromptSubmit — Decision C secret + held PII (observe/confirm only)
    RULE_SECRET_IN_PROMPT: 100,
    RULE_PII_IN_PROMPT: 10,  # HOLD per AIM-602 Decision C; still ranked for attribution
    # PreToolUse — Decision C MCP + restricted-repo
    RULE_UNAPPROVED_MCP: 90,
    RULE_RESTRICTED_REPO: 80,
}


def _managed_enforcement_candidates() -> list[Path]:
    """Platform managed enforcement files; Darwin is first-class (AIM-1170)."""
    plat = sys.platform
    if plat.startswith("win"):
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return [Path(base) / "AI-Monitoring" / "collector" / "enforcement.json"]
    if plat == "darwin":
        return [
            Path(MANAGED_PATH_DARWIN),
            Path(MANAGED_PATH_DARWIN_USER).expanduser(),
            Path(MANAGED_PATH_LINUX),
        ]
    return [Path(MANAGED_PATH_LINUX)]


def policy_path() -> Path | None:
    """First enforcement policy file that exists, in search order."""
    candidates = []
    if os.environ.get("AIM_ENFORCEMENT_FILE"):
        candidates.append(Path(os.environ["AIM_ENFORCEMENT_FILE"]).expanduser())
    candidates.extend(_managed_enforcement_candidates())
    candidates.append(state.state_dir() / "enforcement.json")
    for c in candidates:
        if c.is_file():
            return c
    return None


def default_bundle_path() -> Path:
    """Packaged AIM-296 enforce bundle shipped next to this module (AIM-440)."""
    return Path(__file__).resolve().parent / "default_enforcement.json"


def load_policy() -> dict:
    """Parsed policy dict; {} if no file or unreadable/invalid (fail-open).

    AIM-639: when harden mode is active and the integrity package is present,
    unsigned or signature-invalid enforcement bundles are refused (empty
    policy → observe-only fail-open for *decisions*, but the tamper is
    recorded). This prevents an agent from flipping ``mode: enforce`` to
    ``shadow`` by rewriting a local file without the ops signing key.
    """
    p = policy_path()
    if p is None:
        return {}
    try:
        from collectors.integrity.harden import (  # type: ignore
            append_tamper_event,
            load_signed_json,
        )
    except Exception:
        try:
            import sys
            from pathlib import Path as _P

            root_parent = _P(__file__).resolve().parents[3]  # repo root
            if str(root_parent) not in sys.path:
                sys.path.insert(0, str(root_parent))
            from collectors.integrity.harden import (  # type: ignore
                append_tamper_event,
                load_signed_json,
            )
        except Exception:
            try:
                pol = json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                return {}
            return pol if isinstance(pol, dict) else {}

    res = load_signed_json(p)
    if res.tamper is not None:
        try:
            append_tamper_event(state.state_dir(), res.tamper)
        except Exception:
            pass
    if not res.ok:
        return {}
    return res.payload if isinstance(res.payload, dict) else {}


def seed_default_policy(*, dest: Path | None = None, force: bool = False) -> dict:
    """Install the packaged enforce bundle so declared policy matches reality.

    AIM-440: installers and ``aim join`` previously never delivered
    ``enforcement.json``, so endpoints stayed on an old shadow bake (or no
    bundle) while ``policies/guardrail/v1/core.yaml`` claimed ``mode: enforce``.
    Seeding writes the shipped default to the per-user state dir (or ``dest``)
    unless a managed path already supplies policy.

    Returns a status dict: ``{ok, path, action, policy_hash, mode, …}``.
    Never raises — fail-open for install paths.
    """
    status: dict = {"ok": False, "action": "noop"}
    try:
        src = default_bundle_path()
        if not src.is_file():
            status["error"] = f"packaged bundle missing: {src}"
            return status
        try:
            desired = json.loads(src.read_text())
        except (OSError, json.JSONDecodeError) as e:
            status["error"] = f"packaged bundle unreadable: {e}"
            return status
        if not isinstance(desired, dict):
            status["error"] = "packaged bundle is not an object"
            return status
        desired_hash = _policy_hash(desired) or ""
        desired_mode = desired.get("mode") if isinstance(desired.get("mode"), str) else ""

        managed = next(
            (p for p in _managed_enforcement_candidates() if p.is_file()),
            _managed_enforcement_candidates()[0],
        )

        target = Path(dest) if dest is not None else (state.state_dir() / "enforcement.json")

        if dest is None and managed.is_file() and not force:
            try:
                cur = json.loads(managed.read_text())
            except (OSError, json.JSONDecodeError):
                cur = {}
            status.update({
                "ok": True,
                "action": "managed",
                "path": str(managed),
                "policy_hash": _policy_hash(cur) if isinstance(cur, dict) else None,
                "mode": cur.get("mode") if isinstance(cur, dict) else None,
                "desired_hash": desired_hash,
                "desired_mode": desired_mode,
            })
            return status

        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file() and not force:
            try:
                cur = json.loads(target.read_text())
            except (OSError, json.JSONDecodeError):
                cur = {}
            cur_hash = _policy_hash(cur) if isinstance(cur, dict) else None
            if (cur_hash == desired_hash and isinstance(cur, dict)
                    and cur.get("mode") == desired.get("mode")):
                status.update({
                    "ok": True,
                    "action": "already",
                    "path": str(target),
                    "policy_hash": cur_hash,
                    "mode": cur.get("mode"),
                })
                return status
            action = "upgraded"
        else:
            action = "installed" if not target.is_file() else "replaced"

        target.write_text(json.dumps(desired, indent=2) + "\n")
        status.update({
            "ok": True,
            "action": action,
            "path": str(target),
            "policy_hash": desired_hash,
            "mode": desired_mode,
        })
        return status
    except OSError as e:
        status["error"] = str(e)
        return status


def cohort_subject() -> str:
    """Stable subject for canary membership (AIM-793).

    Prefer enrollment / managed device id (same resolution order as identity
    attestation). Fall back to the local ``host_id`` UUID so an unenrolled
    dogfood host still gets a deterministic bucket. Prefix the kind so a
    device id can never collide with a host UUID of the same string.
    """
    env = os.environ.get("AIM_DEVICE_ID")
    if env and env.strip():
        return f"device:{env.strip()}"
    try:
        from . import config
        cfg = config.load().get("device_id")
        if isinstance(cfg, str) and cfg.strip():
            return f"device:{cfg.strip()}"
    except Exception:
        pass
    try:
        enrolled = (state.state_dir() / "device_id").read_text().strip()
        if enrolled:
            return f"device:{enrolled}"
    except OSError:
        pass
    return f"host:{state.host_id()}"


def parse_cohort(raw) -> dict | None:
    """Normalize a cohort object; None when absent/malformed (no canary gate).

    Shape: ``{"percent": 0..100, "salt": "<non-empty string>"}``.
    ``percent`` may be int or whole-number float. Invalid → treat as no cohort
    so a typo cannot accidentally hard-block the whole fleet (fail-open toward
    the non-canary path; when enforce is on without a valid cohort, enforce
    applies fleet-wide as before AIM-793).
    """
    if not isinstance(raw, dict):
        return None
    percent = raw.get("percent")
    salt = raw.get("salt")
    if isinstance(percent, float) and percent.is_integer():
        percent = int(percent)
    if not isinstance(percent, int) or isinstance(percent, bool):
        return None
    if percent < 0 or percent > 100:
        return None
    if not isinstance(salt, str) or not salt.strip():
        return None
    return {"percent": percent, "salt": salt.strip()}


def cohort_bucket(subject: str, salt: str) -> int:
    """Deterministic 0..99 bucket for ``subject`` under ``salt``.

    Stable across expand steps when salt is held constant: raising percent
    from 5 → 25 keeps every prior member inside the cohort (monotonic canary).
    """
    digest = hashlib.sha256(f"{salt}\n{subject}".encode()).hexdigest()
    return int(digest[:8], 16) % 100


def in_cohort(subject: str, cohort: dict) -> bool:
    """True when ``subject`` is inside the canary for this cohort config."""
    percent = cohort["percent"]
    if percent <= 0:
        return False
    if percent >= 100:
        return True
    return cohort_bucket(subject, cohort["salt"]) < percent


def rule_cohort(pol: dict, rule_id: str) -> dict | None:
    """Per-rule cohort, falling back to top-level policy cohort."""
    rules = pol.get("rules")
    if isinstance(rules, dict):
        entry = rules.get(rule_id)
        if isinstance(entry, dict):
            c = parse_cohort(entry.get("cohort"))
            if c is not None:
                return c
    return parse_cohort(pol.get("cohort"))


def _rule_wants_enforce(pol: dict, rule_id: str) -> bool:
    """True when mode=enforce and the per-rule flag is on (ignores cohort)."""
    if pol.get("mode") != "enforce":
        return False
    rules = pol.get("rules")
    if not isinstance(rules, dict):
        return False
    entry = rules.get(rule_id)
    return isinstance(entry, dict) and entry.get("enforce") is True


def _rule_enforced(pol: dict, rule_id: str, subject: str | None = None) -> bool:
    """True only when mode is enforce, the rule flag is on, and cohort admits.

    Any missing/malformed piece defaults to shadow (fail-open posture).
    Cohort (AIM-793): hosts outside the canary treat the rule as shadow even
    when ``enforce: true`` — expand/rollback is a policy-hash bump only.
    """
    if not _rule_wants_enforce(pol, rule_id):
        return False
    cohort = rule_cohort(pol, rule_id)
    if cohort is None:
        return True
    if subject is None:
        subject = cohort_subject()
    return in_cohort(subject, cohort)


def _cohort_shadow_reason(pol: dict, rule_id: str, subject: str | None = None) -> str | None:
    """Local-only reason suffix when enforce is on but the host is outside the
    canary. Never rides the wire (audit_record is metadata-only)."""
    if not _rule_wants_enforce(pol, rule_id):
        return None
    cohort = rule_cohort(pol, rule_id)
    if cohort is None:
        return None
    if subject is None:
        subject = cohort_subject()
    if in_cohort(subject, cohort):
        return None
    return (f"Outside enforce cohort "
            f"(percent={cohort['percent']}, salt={cohort['salt']!r}); "
            "would_block only until canary expands.")


def active_canary_cohort(pol: dict) -> dict | None:
    """Cohort used for posture ``cohort_member`` reporting.

    Prefers the first enforceable rule that carries a cohort (canary under
    expansion). Falls back to top-level policy cohort. None when no canary is
    configured — posture then omits ``cohort_member``.
    """
    if not pol:
        return None
    rules = pol.get("rules")
    if isinstance(rules, dict):
        for rule_id in ENFORCEABLE_RULES:
            entry = rules.get(rule_id)
            if not isinstance(entry, dict) or entry.get("enforce") is not True:
                continue
            c = parse_cohort(entry.get("cohort"))
            if c is not None:
                return c
        # Any rule with a cohort block, even shadow — still report membership
        # so the report can size a future canary before the flag flips.
        for rule_id in ENFORCEABLE_RULES:
            entry = rules.get(rule_id)
            if not isinstance(entry, dict):
                continue
            c = parse_cohort(entry.get("cohort"))
            if c is not None:
                return c
    return parse_cohort(pol.get("cohort"))
def _rule_action(pol: dict, rule_id: str) -> str:
    """The per-rule applied action: "redact" only when explicitly configured,
    "block" otherwise (default + fail-safe for missing/unknown values)."""
    rules = pol.get("rules")
    entry = rules.get(rule_id) if isinstance(rules, dict) else None
    if isinstance(entry, dict) and entry.get("action") == ACTION_REDACT:
        return ACTION_REDACT
    return ACTION_BLOCK


def _policy_hash(pol: dict) -> str | None:
    h = pol.get("policy_hash")
    return h[:64] if isinstance(h, str) and h else None


def audit_record(pol: dict, decision: Decision,
                 rails: tuple | list | None = None) -> dict:
    """The metadata-only audit record for schema v1.5 `enforcement`.

    When ``rails`` has two or more fired rails (AIM-782 multi-rail), attach
    optional ``rails`` attribution (schema v1.11). Single-rail decisions omit
    the field for back-compat. Never carries content or reason strings.
    """
    rec = {"action": decision.action, "rule_id": decision.rule_id}
    h = _policy_hash(pol)
    if h:
        rec["policy_hash"] = h
    if rails is not None and len(rails) >= 2:
        rec["rails"] = [
            {"rule_id": r.rule_id, "action": r.action} for r in rails
        ]
    return rec


def posture_record(
    pol: dict,
    evaluated: bool,
    *,
    subject: str | None = None,
    enforcement_latency_ms: int | None = None,
) -> dict:
    """The coverage marker for schema v1.7 `enforcement_posture`.

    Emitted on *every* event an enforcement-aware hook produces, decision or
    not. `enforcement` records alone cannot be counted: zero of them is
    equally consistent with "no bundle was ever delivered to this endpoint"
    (a rule physically cannot fire — see the `if not pol: return None` guard
    on every decide_* function), "this collector predates AIM-110", and "the
    fleet is clean". The bake gate needs those separated, so posture carries
    the denominator: policy state, kill-switch mode, and whether this hook
    invocation actually ran the rules.

    AIM-790 (v1.10): optional ``enforcement_latency_ms`` is wall time for the
    local decision path only (metadata). Nested here so latency never needs a
    content-adjacent top-level field. Independent of the fail-open hard
    timeout budget (design: 500 ms).

    AIM-793 (v1.11): when a canary cohort is configured, optional
    ``cohort_member`` (bool) reports whether this host is inside the active
    canary. Privacy-ok: one boolean about config membership, no host id, no
    salt, no content. Omitted when no cohort is configured.
    """
    if not pol:
        rec: dict = {"policy": "absent", "evaluated": bool(evaluated)}
    else:
        rec = {
            "policy": "loaded",
            "mode": "enforce" if pol.get("mode") == "enforce" else "shadow",
            "evaluated": bool(evaluated),
        }
        h = _policy_hash(pol)
        if h:
            rec["policy_hash"] = h
        cohort = active_canary_cohort(pol)
        if cohort is not None:
            if subject is None:
                subject = cohort_subject()
            rec["cohort_member"] = bool(in_cohort(subject, cohort))
    if (
        enforcement_latency_ms is not None
        and isinstance(enforcement_latency_ms, int)
        and not isinstance(enforcement_latency_ms, bool)
        and 0 <= enforcement_latency_ms <= 60000
    ):
        rec["enforcement_latency_ms"] = enforcement_latency_ms
    return rec


# Hooks whose payload the enforcement rules actually run over. Anything else
# (SessionStart/SessionEnd/PostToolUse) reports posture with evaluated=false:
# it proves the endpoint is covered without inflating the prompt denominator.
EVALUATED_HOOKS = ("UserPromptSubmit", "PreToolUse")


def _secret_override_path() -> Path:
    return state.state_dir() / "secret_override.json"


def _secret_override_pending_path() -> Path:
    """Local pending manager-approval requests (AIM-791). Metadata only."""
    return state.state_dir() / "secret_override_pending.json"


def _secret_override_grants_path() -> Path:
    """Local manager grants for secret break-glass (AIM-791). Written by
    control-plane / ops tooling; never contains prompt content."""
    return state.state_dir() / "secret_override_grants.json"


def _secret_override_ttl(pol: dict) -> int:
    raw = pol.get("secret_override_ttl_seconds")
    if isinstance(raw, int) and not isinstance(raw, bool) and 1 <= raw <= SECRET_OVERRIDE_TTL_MAX:
        return raw
    return SECRET_OVERRIDE_TTL_DEFAULT


def _secret_override_requires_manager(pol: dict) -> bool:
    """True when policy demands a manager-approved grant for secret override.

    AIM-784. Default false (pilot resubmit path). Explicit true only — any
    other/missing value is open resubmit so we never silently raise friction.
    """
    return pol.get("secret_override_requires_manager") is True


def _grants_path() -> Path:
    """First break-glass grants file that exists (managed or state-dir)."""
    candidates = []
    env = os.environ.get("AIM_BREAK_GLASS_GRANTS_FILE")
    if env:
        candidates.append(Path(env).expanduser())
    if sys.platform.startswith("win"):
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        candidates.append(
            Path(base) / "AI-Monitoring" / "collector" / "break_glass_grants.json"
        )
    elif sys.platform == "darwin":
        candidates.append(
            Path("/Library/Application Support/AI-Monitoring/collector/break_glass_grants.json")
        )
        candidates.append(
            Path("~/Library/Application Support/AI-Monitoring/collector/break_glass_grants.json").expanduser()
        )
        candidates.append(Path("/etc/aim-collector/break_glass_grants.json"))
    else:
        candidates.append(Path("/etc/aim-collector/break_glass_grants.json"))
    candidates.append(state.state_dir() / "break_glass_grants.json")
    for c in candidates:
        if c.is_file():
            return c
    return candidates[-1]  # default write/read location (state dir)


def load_break_glass_grants(*, now: float | None = None) -> list[dict]:
    """Active (approved, unexpired) grants from the endpoint grants file.

    Shape matches GET /api/enforcement/break-glass/active-grants. Missing or
    corrupt file → empty list (fail-closed for manager-required path means
    "no grant", not "open the door"). Never raises.
    """
    path = _grants_path()
    try:
        if not path.is_file():
            return []
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        raw = data.get("grants")
    elif isinstance(data, list):
        raw = data
    else:
        return []
    if not isinstance(raw, list):
        return []
    now = time.time() if now is None else now
    out: list[dict] = []
    for g in raw:
        if not isinstance(g, dict):
            continue
        status = g.get("status")
        if status is not None and status != "approved":
            continue
        exp = g.get("expires_at")
        if isinstance(exp, str):
            try:
                from datetime import datetime
                exp_s = exp.replace("Z", "+00:00")
                exp_ts = datetime.fromisoformat(exp_s).timestamp()
            except ValueError:
                continue
            if exp_ts <= now:
                continue
        elif exp is not None:
            continue  # unknown expires_at shape: do not honor
        else:
            continue  # no expiry = not a valid time-boxed grant
        out.append(g)
    return out


def grant_allows_override(pol: dict, *, rule_id: str, user_ref: str = "",
                          now: float | None = None) -> bool:
    """True when an active grant in the local grants file covers this rule.

    Deployment model (AIM-784): control-plane grants are subject-scoped, but
    the file landed on the endpoint is already filtered (MDM / agent pull of
    active-grants for this host/user). Presence of an unexpired grant for
    ``rule_id`` is therefore sufficient. When both ``user_ref`` and
    ``subject_user_ref`` are present, they must match (soft defense in depth).
    """
    if rule_id != RULE_SECRET_IN_PROMPT:
        return False
    grants = load_break_glass_grants(now=now)
    for g in grants:
        g_rule = g.get("rule_id") or g.get("ruleId") or RULE_SECRET_IN_PROMPT
        if g_rule != rule_id:
            continue
        subject = g.get("subject_user_ref") or g.get("subjectUserRef") or ""
        if subject and user_ref and subject != user_ref:
            continue
        return True
    return False
    """Policy-gated manager approval for secret break-glass (AIM-791).

    Default **false** — pilot keeps one-step resubmit. Do not enable without
    CEO/Security sign-off (no silent policy expansion).
    """
    raw = pol.get("secret_override_requires_manager")
    if isinstance(raw, bool):
        return raw
    return SECRET_OVERRIDE_REQUIRES_MANAGER_DEFAULT


def _secret_override_manager_grant_ttl(pol: dict) -> int:
    raw = pol.get("secret_override_manager_grant_ttl_seconds")
    if (isinstance(raw, int) and not isinstance(raw, bool)
            and 1 <= raw <= SECRET_OVERRIDE_MANAGER_GRANT_TTL_MAX):
        return raw
    return SECRET_OVERRIDE_MANAGER_GRANT_TTL_DEFAULT


def _challenge_key(session_id: str, prompt: str) -> str:
    """Local-only content hash binding a challenge/override to one prompt in
    one session. Never leaves the machine; not reversible to content."""
    return hashlib.sha256(f"{session_id}\n{prompt}".encode()).hexdigest()


def _request_id_for_key(challenge_key: str) -> str:
    """Short, content-free handle for ops/ticket fields (no prompt material)."""
    return f"bg-{challenge_key[:12]}"


def _load_json_object(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _challenge_outstanding(path: Path, session_id: str, prompt: str, ttl: int,
                           now: float) -> bool:
    """True when an unexpired challenge for this exact prompt+session exists.
    Raises on I/O problems — the caller fails open."""
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return False
    except json.JSONDecodeError:
        return False  # corrupt state file: treat as no outstanding challenge
    if not isinstance(data, dict):
        return False
    ts = data.get(_challenge_key(session_id, prompt))
    return isinstance(ts, (int, float)) and (now - ts) <= ttl


def _record_challenge(path: Path, session_id: str, prompt: str, ttl: int,
                      now: float) -> None:
    """Persist a challenge, pruning expired entries. Raises on I/O problems —
    the caller fails open.

    Expired challenges are dropped silently (no content leaves the endpoint).
    Pilot analytics use durable ``blocked`` / ``confirmed`` audit events —
    an explicit "expiry-not-used" wire event is intentionally not emitted
    (AIM-791: no content, and not needed for the analyst list surface).
    """
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            data = {}
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}  # missing or corrupt state file: start fresh
    data = {k: v for k, v in data.items()
            if isinstance(v, (int, float)) and (now - v) <= ttl}
    data[_challenge_key(session_id, prompt)] = now
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def _manager_grant_active(challenge_key: str, now: float) -> dict | None:
    """Return the active grant record for ``challenge_key``, or None.

    Grant shape (local only)::

        {
          "<challenge_key>": {
            "granted_at": <unix>,
            "expires_at": <unix>,
            "ticket_id": "SEC-1234"   # optional, max 64 chars, no content
          }
        }
    """
    data = _load_json_object(_secret_override_grants_path())
    rec = data.get(challenge_key)
    if not isinstance(rec, dict):
        return None
    expires = rec.get("expires_at")
    if not isinstance(expires, (int, float)) or now > expires:
        return None
    return rec


def _open_manager_approval_request(challenge_key: str, pol: dict,
                                   now: float) -> str:
    """Idempotently open a local manager-approval request. Returns request_id.

    Control-plane / ops tooling can list pending keys under
    ``secret_override_pending.json`` and write grants to
    ``secret_override_grants.json`` (see ``grant_secret_override``).
    """
    grant_ttl = _secret_override_manager_grant_ttl(pol)
    path = _secret_override_pending_path()
    data = _load_json_object(path)
    # prune expired pending
    kept = {}
    for k, v in data.items():
        if not isinstance(v, dict):
            continue
        exp = v.get("expires_at")
        if isinstance(exp, (int, float)) and now <= exp:
            kept[k] = v
    request_id = _request_id_for_key(challenge_key)
    existing = kept.get(challenge_key)
    if isinstance(existing, dict) and existing.get("request_id") == request_id:
        # already open — do not extend silently
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(kept))
        return request_id
    kept[challenge_key] = {
        "opened_at": now,
        "expires_at": now + grant_ttl,
        "request_id": request_id,
        # ticket_id filled by ops when linked to an external ticket
        "ticket_id": None,
        "status": "pending",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(kept))
    return request_id


def grant_secret_override(challenge_key: str, *, ticket_id: str | None = None,
                          ttl_seconds: int | None = None,
                          now: float | None = None,
                          pol: dict | None = None) -> dict:
    """Operator / control-plane helper: grant a secret break-glass override.

    Writes a local grant for ``challenge_key`` (the SHA-256 challenge key from
    pending state — never prompt content). Optional ``ticket_id`` is a short
    external reference (e.g. Jira/ServiceNow id), max 64 chars, alphanumeric
    plus ``-_./``. Returns the grant record. Raises ValueError on bad input.
    """
    if not isinstance(challenge_key, str) or len(challenge_key) != 64:
        raise ValueError("challenge_key must be a 64-char hex digest")
    try:
        int(challenge_key, 16)
    except ValueError as exc:
        raise ValueError("challenge_key must be hex") from exc
    now = time.time() if now is None else now
    pol = pol or {}
    ttl = (ttl_seconds if isinstance(ttl_seconds, int)
           and not isinstance(ttl_seconds, bool)
           and 1 <= ttl_seconds <= SECRET_OVERRIDE_MANAGER_GRANT_TTL_MAX
           else _secret_override_manager_grant_ttl(pol))
    clean_ticket = None
    if ticket_id is not None:
        if not isinstance(ticket_id, str) or not (1 <= len(ticket_id) <= 64):
            raise ValueError("ticket_id must be a 1..64 char string")
        # Reject anything that could smuggle prompt/content characters.
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                      "0123456789-._/")
        if any(c not in allowed for c in ticket_id):
            raise ValueError("ticket_id has disallowed characters")
        clean_ticket = ticket_id
    path = _secret_override_grants_path()
    data = _load_json_object(path)
    # prune expired grants
    pruned = {}
    for k, v in data.items():
        if isinstance(v, dict) and isinstance(v.get("expires_at"), (int, float)) \
                and now <= v["expires_at"]:
            pruned[k] = v
    rec = {
        "granted_at": now,
        "expires_at": now + ttl,
        "ticket_id": clean_ticket,
        "request_id": _request_id_for_key(challenge_key),
    }
    pruned[challenge_key] = rec
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pruned))
    # mark pending request granted if present
    pending_path = _secret_override_pending_path()
    pending = _load_json_object(pending_path)
    if challenge_key in pending and isinstance(pending[challenge_key], dict):
        pending[challenge_key] = {
            **pending[challenge_key],
            "status": "granted",
            "ticket_id": clean_ticket,
            "granted_at": now,
        }
        pending_path.write_text(json.dumps(pending))
    return rec


def decide_prompt(prompt_flags: list[str], pol: dict, *,
                  prompt: str | None = None,
                  session_id: str = "",
                  now: float | None = None) -> Decision | None:
    """UserPromptSubmit: block when a secret:* detector fired on the prompt.

    `prompt_flags` must come from scanning the prompt field only. Returns
    None when no enforceable rule fires (or no policy is deployed).

    Shadow (mode != enforce or per-rule flag off): ``would_block`` — audit
    only, nothing interrupted.

    Enforce (AIM-296): hard block on first submit. Break-glass is one step —
    resubmit the *identical* prompt within ``secret_override_ttl_seconds``;
    the resubmit is audited as ``confirmed`` (schema v1.6 action reused for
    intentional override).

    AIM-791 manager gate (default off): when
    ``secret_override_requires_manager`` is true, a challenge resubmit does
    **not** self-confirm. It opens a local approval request (request id only;
    no content) and stays blocked until ops write a grant via
    ``grant_secret_override`` (ticket id field). Do not enable in pilot
    without CEO/Security sign-off.

    Matched content never leaves the machine; only action + rule_id +
    policy_hash ride the audit event. Fail-open: if local override state
    cannot be read/written, no decision is computed (a block the user can
    never override would be a hard trap).
    """
    if not pol:
        return None
    dets = sorted(f for f in prompt_flags if f.startswith("secret:"))
    if not dets:
        return None
    enforced = _rule_enforced(pol, RULE_SECRET_IN_PROMPT)
    if not enforced:
        cohort_note = _cohort_shadow_reason(pol, RULE_SECRET_IN_PROMPT)
        if cohort_note:
            reason = (f"AI Monitoring: secret pattern detected in prompt "
                      f"({', '.join(dets)}). {cohort_note}")
        else:
            reason = ("AI Monitoring: secret pattern detected in prompt "
                      f"({', '.join(dets)}). Would block if enforce were on.")
        return Decision(RULE_SECRET_IN_PROMPT, "would_block", reason,
                        "UserPromptSubmit")

    # Enforce path: break-glass requires a trackable prompt + session.
    if not isinstance(prompt, str) or not prompt or not session_id:
        # Cannot offer a durable override without state keys — still block,
        # but tell the user to rephrase / contact Security (no silent pass).
        reason = ("Blocked by AI Monitoring: secret pattern detected in prompt "
                  f"({', '.join(dets)}). Rotate the credential if real; rephrase "
                  "to continue. False positive? Contact Security.")
        return Decision(RULE_SECRET_IN_PROMPT, "blocked", reason,
                        "UserPromptSubmit")

    ttl = _secret_override_ttl(pol)
    now = time.time() if now is None else now
    requires_manager = _secret_override_requires_manager(pol)
    ckey = _challenge_key(session_id, prompt)
    try:
        if _challenge_outstanding(_secret_override_path(), session_id, prompt,
                                  ttl, now):
            if requires_manager:
                grant = _manager_grant_active(ckey, now)
                if grant is not None:
                    ticket = grant.get("ticket_id")
                    ticket_note = (f" ticket={ticket}"
                                   if isinstance(ticket, str) and ticket else "")
                    reason = (
                        f"AI Monitoring: secret-pattern block overridden with "
                        f"manager approval ({', '.join(dets)}){ticket_note}. "
                        f"Override is audited."
                    )
                    return Decision(RULE_SECRET_IN_PROMPT, "confirmed", reason,
                                    "UserPromptSubmit")
                # Challenge present but no grant — open/keep pending request.
                request_id = _open_manager_approval_request(ckey, pol, now)
                reason = (
                    "Blocked by AI Monitoring: secret pattern detected in prompt "
                    f"({', '.join(dets)}). Manager approval is required for "
                    f"break-glass (request {request_id}). Contact your manager/"
                    "Security with that id; after approval, resubmit the "
                    "identical prompt. Override is audited when granted."
                )
                return Decision(RULE_SECRET_IN_PROMPT, "blocked", reason,
                                "UserPromptSubmit")
            reason = (f"AI Monitoring: secret-pattern block overridden by "
                      f"resubmission ({', '.join(dets)}). Override is audited.")
            return Decision(RULE_SECRET_IN_PROMPT, "confirmed", reason,
                            "UserPromptSubmit")
        # Also honor an active manager grant when the short challenge TTL has
        # lapsed but the grant has not (manager gate can outlive challenge).
        if requires_manager:
            grant = _manager_grant_active(ckey, now)
            if grant is not None:
                ticket = grant.get("ticket_id")
                ticket_note = (f" ticket={ticket}"
                               if isinstance(ticket, str) and ticket else "")
                reason = (
                    f"AI Monitoring: secret-pattern block overridden with "
                    f"manager approval ({', '.join(dets)}){ticket_note}. "
                    f"Override is audited."
                )
                return Decision(RULE_SECRET_IN_PROMPT, "confirmed", reason,
                                "UserPromptSubmit")
        _record_challenge(_secret_override_path(), session_id, prompt, ttl, now)
    except OSError:
        return None  # fail-open: a block we cannot break-glass is a trap

    if requires_manager:
        reason = (
            "Blocked by AI Monitoring: secret pattern detected in prompt "
            f"({', '.join(dets)}). Rotate the credential if real; rephrase "
            "to continue. Break-glass requires manager approval: resubmit the "
            f"identical prompt within {ttl}s to open an approval request "
            "(audited; not auto-allowed)."
        )
    else:
        reason = (
            "Blocked by AI Monitoring: secret pattern detected in prompt "
            f"({', '.join(dets)}). Rotate the credential if real; rephrase "
            "to continue. Break-glass: resubmit the identical prompt within "
            f"{ttl}s to override (audited)."
        )
    return Decision(RULE_SECRET_IN_PROMPT, "blocked", reason, "UserPromptSubmit")


def split_mcp_tool(tool_name: str) -> tuple[str | None, str | None]:
    """Split ``mcp__<server>__<tool>`` into (server, tool). (None, None) when
    the name is not an MCP tool call; (None, tool) when malformed."""
    if not tool_name.startswith("mcp__"):
        return None, None
    parts = tool_name.split("__", 2)
    if len(parts) < 3 or not parts[2]:
        return None, parts[1] if len(parts) > 1 else None
    return parts[1] or None, parts[2]



def _mcp_override_path() -> Path:
    return state.state_dir() / "mcp_override.json"


def _mcp_override_ttl(pol: dict) -> int:
    raw = pol.get("mcp_override_ttl_seconds")
    if isinstance(raw, int) and not isinstance(raw, bool) and 1 <= raw <= MCP_OVERRIDE_TTL_MAX:
        return raw
    return MCP_OVERRIDE_TTL_DEFAULT


def _tool_matrix_allows(pol: dict, server: str | None, tool: str | None) -> bool:
    """True when tool-level matrix is empty (no restriction) or pair is listed.
    AIM-627: approved_mcp_tools entries are 'server/tool' strings."""
    raw = pol.get("approved_mcp_tools")
    if not isinstance(raw, list) or not raw:
        return True
    if not server or not tool:
        return False
    key = f"{server}/{tool}"
    for entry in raw:
        if isinstance(entry, str) and entry == key:
            return True
        if isinstance(entry, dict) and entry.get("server") == server and entry.get("tool_name") == tool:
            return True
    return False


def decide_pretool(payload: dict, pol: dict, *,
                   session_id: str = "",
                   now: float | None = None) -> Decision | None:
    """PreToolUse: deny MCP calls to servers outside the approved inventory,
    and (AIM-627) tools outside approved_mcp_tools when that matrix is set.

    Unknown/malformed server names count as unapproved (engine semantics).
    Runtime override (analyst-visible via enforcement.action=confirmed):
    resubmit the identical MCP tool_name within mcp_override_ttl_seconds —
    same pattern as secret break-glass. Fail-open if override state I/O fails.
    """
    if not pol:
        return None
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str):
        return None
    server, tool = split_mcp_tool(tool_name)
    is_mcp = tool_name.startswith("mcp__")
    if not is_mcp:
        return None
    approved = pol.get("approved_mcp_servers")
    approved = {s for s in approved if isinstance(s, str)} if isinstance(approved, list) else set()
    server_ok = server is not None and server in approved
    tool_ok = _tool_matrix_allows(pol, server, tool)
    if server_ok and tool_ok:
        return None

    # Prefer specific rule id for tool-level vs server-level.
    if server_ok and not tool_ok:
        rule_id = "unapproved-mcp-tool"
        name = f"{server}/{tool or 'unknown'}"
        reason_core = (f"MCP tool '{name}' is not on the approved tool matrix")
    else:
        rule_id = RULE_UNAPPROVED_MCP
        name = server or "unknown"
        reason_core = (f"MCP server '{name}' is not on the approved inventory")

    # Tool-level matrix denials ride the same endpoint enforce flag as
    # unapproved-mcp-server until a dedicated rule flip ships.
    enforced = _rule_enforced(pol, RULE_UNAPPROVED_MCP)

    if not enforced:
        reason = (f"AI Monitoring: {reason_core}. Would block if enforce were on.")
        return Decision(rule_id, "would_block", reason, "PreToolUse")

    # Enforce path with optional break-glass (AIM-627).
    sid = session_id or (payload.get("session_id") if isinstance(payload.get("session_id"), str) else "") or ""
    ttl = _mcp_override_ttl(pol)
    now = time.time() if now is None else now
    if sid:
        try:
            if _challenge_outstanding(_mcp_override_path(), sid, tool_name, ttl, now):
                reason = (f"AI Monitoring: {reason_core} — overridden by resubmission "
                          f"(audited). Contact Security for permanent allowlist.")
                return Decision(rule_id, "confirmed", reason, "PreToolUse")
            _record_challenge(_mcp_override_path(), sid, tool_name, ttl, now)
        except OSError:
            return None  # fail-open

    reason = (f"Blocked by AI Monitoring: {reason_core}. Contact Security to "
              f"get it approved, or remove it from your MCP config. Break-glass: "
              f"retry the identical tool call within {ttl}s to override (audited).")
    return Decision(rule_id, "blocked", reason, "PreToolUse")

    name = server or "unknown"
    if enforced:
        reason = (f"Blocked by AI Monitoring: MCP server '{name}' is not on the "
                  "approved inventory. Contact Security to get it approved, or "
                  "remove it from your MCP config.")
    else:
        cohort_note = _cohort_shadow_reason(pol, RULE_UNAPPROVED_MCP)
        if cohort_note:
            reason = (f"AI Monitoring: MCP server '{name}' is not on the "
                      f"approved inventory. {cohort_note}")
        else:
            reason = (f"AI Monitoring: MCP server '{name}' is not on the "
                      "approved inventory. Would block if enforce were on.")
    return Decision(RULE_UNAPPROVED_MCP,
                    "blocked" if enforced else "would_block",
                    reason, "PreToolUse")

    if not enforced:
        reason = (f"AI Monitoring: {reason_core}. Would block if enforce were on.")
        return Decision(rule_id, "would_block", reason, "PreToolUse")

    # Enforce path with optional break-glass (AIM-627).
    sid = session_id or (payload.get("session_id") if isinstance(payload.get("session_id"), str) else "") or ""
    ttl = _mcp_override_ttl(pol)
    now = time.time() if now is None else now
    if sid:
        try:
            if _challenge_outstanding(_mcp_override_path(), sid, tool_name, ttl, now):
                reason = (f"AI Monitoring: {reason_core} — overridden by resubmission "
                          f"(audited). Contact Security for permanent allowlist.")
                return Decision(rule_id, "confirmed", reason, "PreToolUse")
            _record_challenge(_mcp_override_path(), sid, tool_name, ttl, now)
        except OSError:
            return None  # fail-open

    reason = (f"Blocked by AI Monitoring: {reason_core}. Contact Security to "
              f"get it approved, or remove it from your MCP config. Break-glass: "
              f"retry the identical tool call within {ttl}s to override (audited).")
    return Decision(rule_id, "blocked", reason, "PreToolUse")



def deny_output(decision: Decision) -> dict:
    """Claude Code hook JSON decision contract for a block.

    UserPromptSubmit: {"decision": "block", "reason": ...} — prompt is not
    processed, reason is shown to the user. PreToolUse: permissionDecision
    "deny" — the tool call is denied, reason shown to Claude. (Exit-2 is the
    alternate blocking channel; we use the JSON contract and our failure
    posture is fail-open anyway, so a hook that cannot emit JSON simply
    observes.)"""
    if decision.hook_event == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": decision.reason,
            }
        }
    return {"decision": "block", "reason": decision.reason}


# ---------------------------------------------------------------------------
# AIM-320: inline redaction — secret-in-tool-input (PreToolUse updatedInput)
# ---------------------------------------------------------------------------


def _redact_prefixes(pol: dict) -> tuple[str, ...]:
    """Detector prefixes redaction may rewrite. Default is secret-only — the
    high-precision rules that passed the AIM-296 corpus gate. Structured PII
    is opt-in via policy; injection prose patterns are never redactable."""
    raw = pol.get("redact_prefixes")
    if isinstance(raw, list):
        prefixes = tuple(s for s in raw if isinstance(s, str) and s)
        if prefixes:
            return prefixes
    return matchers.REDACT_PREFIXES_DEFAULT


def _redact_value(value, prefixes: tuple[str, ...], detectors: set[str]):
    """Recursively redact string leaves of a tool_input structure."""
    if isinstance(value, str):
        r = matchers.redact_text(value, prefixes)
        detectors.update(r.detectors)
        return r.text
    if isinstance(value, list):
        return [_redact_value(v, prefixes, detectors) for v in value]
    if isinstance(value, dict):
        return {k: _redact_value(v, prefixes, detectors) for k, v in value.items()}
    return value


def decide_redact_tool_input(payload: dict, pol: dict) -> Decision | None:
    """PreToolUse: replace secret literals in tool_input so the call proceeds
    without the secret ever leaving the host (AIM-320).

    Shadow: ``would_block`` — audit only, input untouched. Enforce +
    ``action: "redact"``: ``redacted`` with the rewritten input attached —
    the hook emits it as PreToolUse ``updatedInput`` and the tool call runs
    with placeholders. Enforce + default action: ``blocked`` (deny).

    Detection runs the full multi-pass scan; redaction rewrites raw-text
    spans only. If any eligible detector still fires on the redacted
    structure — content that matched solely after normalization, whitespace
    deletion, or base64 decoding, i.e. evasion — the decision falls back to
    ``blocked``: redacted-but-still-secret output must never egress.
    Fail-open per the global rule: any matcher error is contained by the
    hook's outer guard and degrades to observe.
    """
    if not pol:
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    prefixes = _redact_prefixes(pol)
    flags = sorted(f for f in matchers.scan_obj(tool_input)
                   if f.startswith(prefixes))
    if not flags:
        return None
    dets = ", ".join(flags)
    if not _rule_enforced(pol, RULE_SECRET_IN_TOOL_INPUT):
        reason = ("AI Monitoring: secret pattern in tool input "
                  f"({dets}). Would be redacted before sending if "
                  "enforce were on.")
        return Decision(RULE_SECRET_IN_TOOL_INPUT, "would_block", reason,
                        "PreToolUse")
    if _rule_action(pol, RULE_SECRET_IN_TOOL_INPUT) != ACTION_REDACT:
        reason = ("Blocked by AI Monitoring: secret pattern in tool input "
                  f"({dets}). Rotate the credential if real; "
                  "remove it to proceed. False positive? Contact Security.")
        return Decision(RULE_SECRET_IN_TOOL_INPUT, "blocked", reason,
                        "PreToolUse")
    detectors: set[str] = set()
    redacted = _redact_value(tool_input, prefixes, detectors)
    residual = sorted(f for f in matchers.scan_obj(redacted)
                      if f.startswith(prefixes))
    if residual:
        reason = ("Blocked by AI Monitoring: secret pattern in tool input "
                  f"({', '.join(residual)}) is encoded/obfuscated and "
                  "cannot be safely redacted. Rotate the credential if real; "
                  "remove it to proceed. False positive? Contact Security.")
        return Decision(RULE_SECRET_IN_TOOL_INPUT, "blocked", reason,
                        "PreToolUse")
    reason = ("AI Monitoring redacted secret pattern(s) "
              f"({dets}) from this tool call before it was sent — "
              "the credential never left your machine; the call is running "
              "with [REDACTED:...] placeholders. Rotate the credential if "
              "real. Questions or false positive? Contact Security. "
              f"(policy: {RULE_SECRET_IN_TOOL_INPUT})")
    return Decision(RULE_SECRET_IN_TOOL_INPUT, "redacted", reason,
                    "PreToolUse", updated_input=redacted)


def redact_output(decision: Decision) -> dict:
    """Claude Code hook JSON contract for an applied redaction: allow the
    PreToolUse call with the redacted input substituted. The reason is shown
    to the user/agent; the markers in the updated input show exactly what was
    removed."""
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": decision.reason,
            "updatedInput": decision.updated_input,
        }
    }


# ---------------------------------------------------------------------------
# AIM-111 Phase 2a: restricted-repo-access + pii-in-prompt (confirm-prompt)
# ---------------------------------------------------------------------------


def _restricted_repo_override_path() -> Path:
    return state.state_dir() / "restricted_repo_override.json"


def _restricted_repo_override_ttl(pol: dict) -> int:
    raw = pol.get("restricted_repo_override_ttl_seconds")
    if (isinstance(raw, int) and not isinstance(raw, bool)
            and 1 <= raw <= RESTRICTED_REPO_OVERRIDE_TTL_MAX):
        return raw
    return RESTRICTED_REPO_OVERRIDE_TTL_DEFAULT


def _restricted_roots(pol: dict) -> list[str]:
    """Normalized restricted-repo roots from policy; [] when unset/malformed
    (fail-open: an unparseable list disables the rule rather than blocking
    everything)."""
    raw = pol.get("restricted_repo_paths")
    if not isinstance(raw, list):
        return []
    roots = []
    for r in raw:
        if isinstance(r, str) and r.strip():
            roots.append(os.path.normpath(os.path.expanduser(r.strip())))
    return roots


def _path_under(path: str, roots: list[str]) -> str | None:
    """The restricted root containing `path`, or None. Boundary-safe: a root
    matches itself and its descendants, not siblings that share a prefix."""
    p = os.path.normpath(os.path.expanduser(path))
    for root in roots:
        if p == root or p.startswith(root + os.sep):
            return root
    return None


def decide_restricted_repo(payload: dict, pol: dict, *,
                           session_id: str = "",
                           now: float | None = None,
                           dry_run: bool = False) -> Decision | None:
    """PreToolUse: deny file-touching tool calls whose path sits under a
    restricted root. Tools without a path input (incl. Bash free text) are
    out of scope and never fire here.

    AIM-782: MCP tools that carry a path key are evaluated here too — they
    may co-fire with ``unapproved-mcp-server``. The multi-rail orchestrator
    picks a single primary; both rails are attributed on the audit event.

    AIM-566: when enforce is on, resubmitting the identical tool+path inside
    ``restricted_repo_override_ttl_seconds`` is the audited break-glass
    (action ``confirmed``). Challenge state is local-only. ``dry_run=True``
    returns the first-hit decision without writing challenge state — used
    when a higher-precedence rail already won.
    """
    if not pol:
        return None
    roots = _restricted_roots(pol)
    if not roots:
        return None
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str):
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    for key in _PATH_INPUT_KEYS:
        val = tool_input.get(key)
        if not isinstance(val, str) or not val.strip():
            continue
        hit = _path_under(val, roots)
        if hit is None:
            continue
        enforced = _rule_enforced(pol, RULE_RESTRICTED_REPO)
        if not enforced:
            cohort_note = _cohort_shadow_reason(pol, RULE_RESTRICTED_REPO)
            if cohort_note:
                reason = (f"AI Monitoring: '{hit}' is a restricted repository "
                          f"(policy: restricted-repo-access). {cohort_note}")
            else:
                reason = (f"AI Monitoring: '{hit}' is a restricted repository "
                          "(policy: restricted-repo-access). Would block if "
                          "enforce were on.")
            return Decision(RULE_RESTRICTED_REPO, "would_block", reason,
                            "PreToolUse")
        if dry_run:
            reason = (f"Blocked by AI Monitoring: '{hit}' is a restricted "
                      "repository (policy: restricted-repo-access).")
            return Decision(RULE_RESTRICTED_REPO, "blocked", reason,
                            "PreToolUse")
        sid = session_id or (
            payload.get("session_id")
            if isinstance(payload.get("session_id"), str) else ""
        ) or ""
        ttl = _restricted_repo_override_ttl(pol)
        now = time.time() if now is None else now
        # Bind the override to one tool + one normalized path. The matched
        # path never leaves the endpoint (audit is action+rule+hash only).
        challenge = f"{tool_name}\n{os.path.normpath(os.path.expanduser(val))}"
        if sid:
            try:
                if _challenge_outstanding(
                        _restricted_repo_override_path(), sid, challenge,
                        ttl, now):
                    reason = (
                        f"AI Monitoring: '{hit}' is a restricted repository "
                        "(policy: restricted-repo-access) — overridden by "
                        "resubmission (audited). Contact Security for a "
                        "permanent path exception."
                    )
                    return Decision(RULE_RESTRICTED_REPO, "confirmed", reason,
                                    "PreToolUse")
                _record_challenge(
                    _restricted_repo_override_path(), sid, challenge, ttl, now)
            except OSError:
                return None  # fail-open: a trap block the user cannot override
        reason = (
            f"Blocked by AI Monitoring: '{hit}' is a restricted "
            "repository (policy: restricted-repo-access). Work from "
            "an approved location, or contact Security for an "
            f"exception. Break-glass: retry the identical tool call "
            f"on the same path within {ttl}s to override (audited)."
        )
        return Decision(RULE_RESTRICTED_REPO, "blocked", reason, "PreToolUse")
    return None


def _pii_low_sensitivity(pol: dict) -> frozenset:
    raw = pol.get("pii_low_sensitivity_detectors")
    if isinstance(raw, list):
        return frozenset(s for s in raw if isinstance(s, str))
    return frozenset(PII_LOW_SENSITIVITY_DEFAULT)


def eligible_pii_flags(prompt_flags: list[str], pol: dict) -> list[str]:
    """The pii:* detectors that are enforcement-eligible for pii-in-prompt.

    High-sensitivity structured PII is always eligible. Low-sensitivity PII
    (email, by default) is eligible only when it co-occurs with another
    sensitive signal (structured PII or a secret) — a bare email in a coding
    context is normal content, not exfiltration (AIM-128). Returns sorted flags;
    an empty result means no confirm-prompt decision is computed at all."""
    low = _pii_low_sensitivity(pol)
    pii = [f for f in prompt_flags if f.startswith("pii:")]
    high = [f for f in pii if f not in low]
    has_other_sensitive = bool(high) or any(
        f.startswith("secret:") for f in prompt_flags)
    eligible = list(high)
    if has_other_sensitive:
        eligible += [f for f in pii if f in low]
    return sorted(eligible)


def _pii_confirm_path() -> Path:
    return state.state_dir() / "pii_confirm.json"


def _pii_confirm_key(session_id: str, prompt: str) -> str:
    """Local-only content hash binding a challenge to one prompt in one
    session. Never leaves the machine; not reversible to content."""
    return hashlib.sha256(f"{session_id}\n{prompt}".encode()).hexdigest()


def _pii_confirm_ttl(pol: dict) -> int:
    raw = pol.get("pii_confirm_ttl_seconds")
    if isinstance(raw, int) and not isinstance(raw, bool) and 1 <= raw <= PII_CONFIRM_TTL_MAX:
        return raw
    return PII_CONFIRM_TTL_DEFAULT


def _pii_challenge_outstanding(session_id: str, prompt: str, ttl: int,
                               now: float) -> bool:
    """True when an unexpired challenge for this exact prompt+session exists.
    Raises on I/O problems — the caller fails open."""
    try:
        data = json.loads(_pii_confirm_path().read_text())
    except FileNotFoundError:
        return False
    except json.JSONDecodeError:
        return False  # corrupt state file: treat as no outstanding challenge
    if not isinstance(data, dict):
        return False
    ts = data.get(_pii_confirm_key(session_id, prompt))
    return isinstance(ts, (int, float)) and (now - ts) <= ttl


def _pii_record_challenge(session_id: str, prompt: str, ttl: int,
                          now: float) -> None:
    """Persist a challenge, pruning expired entries. Raises on I/O problems —
    the caller fails open."""
    path = _pii_confirm_path()
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            data = {}
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}  # missing or corrupt state file: start fresh
    data = {k: v for k, v in data.items()
            if isinstance(v, (int, float)) and (now - v) <= ttl}
    data[_pii_confirm_key(session_id, prompt)] = now
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def decide_pii_confirm(prompt, prompt_flags: list[str], pol: dict,
                       session_id: str, now: float | None = None,
                       *, dry_run: bool = False) -> Decision | None:
    """UserPromptSubmit: confirm-prompt for PII patterns (NOT a hard block).

    Shadow: ``would_block`` (challenge would have fired). Enforce, first
    submission: ``blocked`` with a challenge reason — the user resubmits the
    identical prompt within the TTL to confirm. Enforce, resubmission in
    window: ``confirmed`` — the prompt proceeds, audited. Fail-open: if the
    local challenge state cannot be read/written, no decision is computed
    (a confirm the user can never complete would be a hard block by accident).

    ``dry_run=True`` (AIM-782 multi-rail attribution): return what this rail
    would decide without recording a challenge. Used when a higher-precedence
    rail already won so PII challenge state is never written on a dual-rail
    secret+PII prompt.
    """
    if not pol or not isinstance(prompt, str) or not prompt:
        return None
    dets = eligible_pii_flags(prompt_flags, pol)
    if not dets:
        return None
    if not _rule_enforced(pol, RULE_PII_IN_PROMPT):
        cohort_note = _cohort_shadow_reason(pol, RULE_PII_IN_PROMPT)
        if cohort_note:
            reason = (f"AI Monitoring: PII-like pattern detected in prompt "
                      f"({', '.join(dets)}). {cohort_note}")
        else:
            reason = ("AI Monitoring: PII-like pattern detected in prompt "
                      f"({', '.join(dets)}).")
        return Decision(RULE_PII_IN_PROMPT, "would_block", reason,
                        "UserPromptSubmit")
    if dry_run:
        # Attribution only: first-submit challenge would fire; no state write.
        reason = ("AI Monitoring: PII-like pattern detected in prompt "
                  f"({', '.join(dets)}).")
        return Decision(RULE_PII_IN_PROMPT, "blocked", reason,
                        "UserPromptSubmit")
    ttl = _pii_confirm_ttl(pol)
    now = time.time() if now is None else now
    try:
        if _pii_challenge_outstanding(session_id, prompt, ttl, now):
            reason = (f"AI Monitoring: PII pattern ({', '.join(dets)}) "
                      "confirmed by resubmission.")
            return Decision(RULE_PII_IN_PROMPT, "confirmed", reason,
                            "UserPromptSubmit")
        _pii_record_challenge(session_id, prompt, ttl, now)
    except OSError:
        return None  # fail-open: a challenge we cannot track is a trap
    reason = ("AI Monitoring: PII-like pattern detected in prompt "
              f"({', '.join(dets)}). Resubmit the identical prompt within "
              f"{ttl}s to confirm you intend to send it, or rephrase to "
              "remove it.")
    return Decision(RULE_PII_IN_PROMPT, "blocked", reason, "UserPromptSubmit")


def _rail_rank(decision: Decision) -> int:
    return RAIL_PRECEDENCE.get(decision.rule_id, 0)


def select_primary(candidates: list) -> OrchestratedDecision | None:
    """Pick the single primary rail from candidates by deterministic
    precedence. Stable sort: higher rank first; ties break on rule_id
    ascending so the selection is fully deterministic even if two rails
    share a rank (should not happen for Decision C)."""
    fired = [c for c in candidates if c is not None]
    if not fired:
        return None
    ordered = sorted(fired, key=lambda d: (-_rail_rank(d), d.rule_id))
    return OrchestratedDecision(decision=ordered[0], rails=tuple(ordered))


def orchestrate_prompt(prompt_flags: list[str], pol: dict, *,
                       prompt: str | None = None,
                       session_id: str = "",
                       now: float | None = None) -> OrchestratedDecision | None:
    """UserPromptSubmit multi-rail: secret > pii (PII HOLD for enforce policy).

    Evaluates secret first with real side effects (break-glass state). When
    secret fires, PII is evaluated dry-run for attribution only so a dual-rail
    prompt never records a PII challenge and never double-blocks.
    """
    if not pol:
        return None
    secret = decide_prompt(prompt_flags, pol, prompt=prompt,
                           session_id=session_id, now=now)
    pii = decide_pii_confirm(
        prompt, prompt_flags, pol, session_id, now=now,
        dry_run=secret is not None,
    )
    return select_primary([secret, pii])


def orchestrate_pretool(payload: dict, pol: dict, *,
                       now: float | None = None) -> OrchestratedDecision | None:
    """PreToolUse multi-rail: unapproved-mcp > restricted-repo (Decision C).

    Both rails may write local break-glass challenge state. When MCP fires,
    restricted-repo is evaluated ``dry_run`` so a dual-rail invocation does
    not record a repo challenge the user never saw as the primary actuation.
    """
    if not pol:
        return None
    mcp = decide_pretool(payload, pol, now=now)
    repo = decide_restricted_repo(
        payload, pol, now=now, dry_run=mcp is not None)
    return select_primary([mcp, repo])


def orchestrate(payload: dict, pol: dict, *,
                prompt_flags: list[str] | None = None,
                now: float | None = None) -> OrchestratedDecision | None:
    """Hook-level multi-rail orchestrator (AIM-782).

    Returns a single OrchestratedDecision or None. Fail-open: callers wrap
    this; any exception degrades to observe. Never emits more than one
    primary actuation per invocation.
    """
    if not pol:
        return None
    hook_name = payload.get("hook_event_name", "")
    if hook_name == "UserPromptSubmit":
        prompt = payload.get("prompt")
        session_id = payload.get("session_id") or ""
        flags = prompt_flags if prompt_flags is not None else []
        return orchestrate_prompt(
            flags, pol,
            prompt=prompt if isinstance(prompt, str) else None,
            session_id=session_id,
            now=now,
        )
    if hook_name == "PreToolUse":
        return orchestrate_pretool(payload, pol, now=now)
    return None
# ---------------------------------------------------------------------------
# AIM-792: multi-rail orchestration (single decision per hook invocation)
# ---------------------------------------------------------------------------
#
# When more than one rail *could* fire on the same UserPromptSubmit /
# PreToolUse payload, exactly one Decision is selected and applied. The
# audit trail carries that one action; stdout carries at most one JSON
# actuation (deny OR allow+updatedInput — never both).
#
# Precedence is fixed product policy (not "all firing rails run"):
#
#   UserPromptSubmit:
#     1. secret-pattern-in-prompt  (block / break-glass confirmed)
#     2. pii-in-prompt            (confirm challenge)
#
#   PreToolUse:
#     1. secret-in-tool-input     (redact; residual non-redactable → block)
#     2. unapproved-mcp-server
#     3. restricted-repo-access
#
# A higher-precedence rail that returns any Decision (including shadow
# ``would_block``) short-circuits lower rails — matching the prior
# cascade in hook.py, now centralized so hook/tests cannot reintroduce
# dual-enforce races by calling rails out of order.


def decide_user_prompt_submit(prompt, prompt_flags: list[str], pol: dict,
                              session_id: str,
                              now: float | None = None) -> Decision | None:
    """Single entry for UserPromptSubmit multi-rail selection (AIM-792).

    Precedence: secret-pattern-in-prompt > pii-in-prompt. Returns at most
    one Decision. ``None`` means no rail fired (or no policy).
    """
    if not pol:
        return None
    decision = decide_prompt(
        prompt_flags, pol,
        prompt=prompt if isinstance(prompt, str) else None,
        session_id=session_id or "",
        now=now,
    )
    if decision is not None:
        return decision
    return decide_pii_confirm(prompt, prompt_flags, pol, session_id or "",
                              now=now)


def decide_pretool_use(payload: dict, pol: dict, *,
                      now: float | None = None) -> Decision | None:
    """Single entry for PreToolUse multi-rail selection (AIM-792).

    Precedence: secret-in-tool-input (redact/block) > unapproved-mcp-server
    > restricted-repo-access. Returns at most one Decision. ``None`` means
    no rail fired (or no policy).
    """
    if not pol:
        return None
    decision = decide_redact_tool_input(payload, pol)
    if decision is not None:
        return decision
    decision = decide_pretool(payload, pol, now=now)
    if decision is not None:
        return decision
    return decide_restricted_repo(payload, pol, now=now)
