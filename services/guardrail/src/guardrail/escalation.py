"""Multi-stage escalation policies for alert routing (AIM-699).

Wave-1 destinations fan out simultaneously. Escalation policies add ordered
stages with timers so SOC can page Slack first and PagerDuty only if the
finding is still open (``status='new'``) after a configured delay.

Policy shape (under ``settings.alerts``)::

    escalation_policies:
      - id: soc-oncall
        min_severity: high          # optional; default low (all)
        rule_ids: []                # empty / omitted = all rules
        stages:
          - after_seconds: 0        # stage 0 fires with the finding insert
            destinations: [slack]
          - after_seconds: 900      # wait 15m after previous stage
            destinations: [pagerduty]

Semantics
---------
* Destinations listed in stages fire **only** when that stage is due.
* Destinations **not** listed in any stage of the matched policy still fan
  out immediately (bus / SIEM / webhook-as-log stay independent of paging).
* If no policy matches a finding, every configured notifier fires
  immediately (pre-AIM-699 behaviour).
* Later stages are cancelled when the finding leaves ``status='new'``
  (acknowledged / resolved / false_positive).
* ``after_seconds`` on stage 0 must be 0; later stages count from the
  moment the previous stage was delivered (or enrolled for stage 0).

This module is pure policy parsing + SQL-backed state machine. Delivery
still goes through ``dbrunner.deliver_batch`` so audit rows stay one
place.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

from .notify import SEVERITY_ORDER

# Destinations that are always immediate even when a policy matches —
# audit/export rails, not paging. Stage lists may still mention them; if
# they do, stage timing applies. If they do not appear in any stage they
# still fire at t=0 via the "not in policy stages" path.
KNOWN_DESTINATIONS = frozenset({
    "webhook",
    "sentinel",
    "bus",
    "splunk_hec",
    "syslog_cef",
    "google_chat",
    "slack",
    "pagerduty",
    "email",
})

OPEN_STATUSES = frozenset({"new"})


class EscalationPolicyError(ValueError):
    """Raised when an escalation policy is malformed at load time."""


@dataclass(frozen=True)
class EscalationStage:
    after_seconds: int
    destinations: tuple[str, ...]


@dataclass(frozen=True)
class EscalationPolicy:
    id: str
    stages: tuple[EscalationStage, ...]
    min_severity: str = "low"
    rule_ids: frozenset[str] = field(default_factory=frozenset)

    def matches(self, finding: dict) -> bool:
        sev = finding.get("severity") or "low"
        if SEVERITY_ORDER.get(sev, 0) < SEVERITY_ORDER.get(self.min_severity, 0):
            return False
        if self.rule_ids and finding.get("rule_id") not in self.rule_ids:
            return False
        return True

    def all_stage_destinations(self) -> frozenset[str]:
        out: set[str] = set()
        for stage in self.stages:
            out.update(stage.destinations)
        return frozenset(out)

    def stage_destinations(self, index: int) -> tuple[str, ...]:
        if index < 0 or index >= len(self.stages):
            return ()
        return self.stages[index].destinations


def parse_escalation_policies(alerts: dict | None) -> list[EscalationPolicy]:
    """Parse ``settings.alerts.escalation_policies``. Empty / missing → []."""
    alerts = alerts or {}
    raw = alerts.get("escalation_policies")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise EscalationPolicyError("escalation_policies must be a list")
    policies: list[EscalationPolicy] = []
    seen_ids: set[str] = set()
    for idx, item in enumerate(raw):
        policies.append(_parse_one(item, idx, seen_ids))
    return policies


def _parse_one(item: Any, idx: int, seen_ids: set[str]) -> EscalationPolicy:
    where = f"escalation_policies[{idx}]"
    if not isinstance(item, dict):
        raise EscalationPolicyError(f"{where} must be a mapping")
    pid = item.get("id")
    if not pid or not isinstance(pid, str):
        raise EscalationPolicyError(f"{where}: missing string 'id'")
    if pid in seen_ids:
        raise EscalationPolicyError(f"{where}: duplicate policy id {pid!r}")
    seen_ids.add(pid)

    min_sev = item.get("min_severity") or "low"
    if min_sev not in SEVERITY_ORDER:
        raise EscalationPolicyError(
            f"{where}: min_severity must be one of {sorted(SEVERITY_ORDER)}, got {min_sev!r}"
        )

    rule_ids_raw = item.get("rule_ids") or []
    if not isinstance(rule_ids_raw, list) or any(not isinstance(r, str) for r in rule_ids_raw):
        raise EscalationPolicyError(f"{where}: rule_ids must be a list of strings")
    rule_ids = frozenset(rule_ids_raw)

    stages_raw = item.get("stages")
    if not isinstance(stages_raw, list) or not stages_raw:
        raise EscalationPolicyError(f"{where}: stages must be a non-empty list")

    stages: list[EscalationStage] = []
    for sidx, stage in enumerate(stages_raw):
        stages.append(_parse_stage(stage, f"{where}.stages[{sidx}]", sidx))

    return EscalationPolicy(
        id=pid,
        stages=tuple(stages),
        min_severity=min_sev,
        rule_ids=rule_ids,
    )


def _parse_stage(stage: Any, where: str, sidx: int) -> EscalationStage:
    if not isinstance(stage, dict):
        raise EscalationPolicyError(f"{where} must be a mapping")
    after = stage.get("after_seconds", 0 if sidx == 0 else None)
    if after is None:
        raise EscalationPolicyError(f"{where}: missing 'after_seconds'")
    if isinstance(after, bool) or not isinstance(after, int) or after < 0:
        raise EscalationPolicyError(f"{where}: after_seconds must be an int >= 0")
    if sidx == 0 and after != 0:
        raise EscalationPolicyError(f"{where}: stage 0 after_seconds must be 0 (fires immediately)")
    if sidx > 0 and after == 0:
        raise EscalationPolicyError(
            f"{where}: later stages need after_seconds > 0 (use stage 0 for immediate)"
        )

    dests = stage.get("destinations")
    if not isinstance(dests, list) or not dests:
        raise EscalationPolicyError(f"{where}: destinations must be a non-empty list")
    cleaned: list[str] = []
    for d in dests:
        if not isinstance(d, str) or not d:
            raise EscalationPolicyError(f"{where}: destination entries must be non-empty strings")
        if d not in KNOWN_DESTINATIONS:
            raise EscalationPolicyError(
                f"{where}: unknown destination {d!r} (known: {sorted(KNOWN_DESTINATIONS)})"
            )
        if d not in cleaned:
            cleaned.append(d)
    return EscalationStage(after_seconds=after, destinations=tuple(cleaned))


def match_policy(
    finding: dict, policies: Sequence[EscalationPolicy]
) -> EscalationPolicy | None:
    """First matching policy wins (document order)."""
    for policy in policies:
        if policy.matches(finding):
            return policy
    return None


def partition_notifiers_for_findings(
    notifiers: list,
    findings: list[dict],
    policies: Sequence[EscalationPolicy],
) -> tuple[list[tuple[list, list[dict]]], list[tuple[EscalationPolicy, list[dict]]]]:
    """Split findings into delivery groups for the initial insert path.

    Returns
    -------
    delivery_groups
        List of ``(notifiers_subset, findings)`` for ``deliver_batch``.
        Findings with no matching policy get the full notifier list.
        Policy-matched findings get stage-0 destinations + any destination
        not listed in the policy's stages.
    enrollments
        ``(policy, findings)`` pairs that need escalation state rows.
    """
    if not policies:
        return ([(notifiers, findings)] if findings else []), []

    no_policy: list[dict] = []
    by_policy: dict[str, tuple[EscalationPolicy, list[dict]]] = {}
    for finding in findings:
        policy = match_policy(finding, policies)
        if policy is None:
            no_policy.append(finding)
        else:
            bucket = by_policy.get(policy.id)
            if bucket is None:
                by_policy[policy.id] = (policy, [finding])
            else:
                bucket[1].append(finding)

    groups: list[tuple[list, list[dict]]] = []
    if no_policy:
        groups.append((notifiers, no_policy))

    enrollments: list[tuple[EscalationPolicy, list[dict]]] = []
    for policy, group in by_policy.values():
        selected = _notifiers_for_stage(notifiers, policy, stage_index=0, include_non_stage=True)
        if selected and group:
            groups.append((selected, group))
        enrollments.append((policy, group))
    return groups, enrollments


def _notifiers_for_stage(
    notifiers: list,
    policy: EscalationPolicy,
    *,
    stage_index: int,
    include_non_stage: bool,
) -> list:
    stage_dests = set(policy.stage_destinations(stage_index))
    all_stage = policy.all_stage_destinations()
    selected = []
    for n in notifiers:
        dest = getattr(n, "destination", None)
        if dest in stage_dests:
            selected.append(n)
        elif include_non_stage and dest not in all_stage:
            # Destination is not part of the escalation ladder — keep fan-out.
            selected.append(n)
    return selected


# -- SQL state machine -------------------------------------------------------

ENROLL_SQL = """
INSERT INTO finding_escalation_state
  (finding_id, policy_id, stage_index, next_stage_at, status, updated_at)
VALUES (%s, %s, %s, %s, %s, now())
ON CONFLICT (finding_id) DO NOTHING
"""

DUE_SQL = """
SELECT e.finding_id, e.policy_id, e.stage_index,
       f.ts, f.rule_id, f.severity, f.title, f.subject, f.evidence,
       f.policy_hash, f.decision, f.status AS finding_status
FROM finding_escalation_state e
JOIN findings f ON f.finding_id = e.finding_id
WHERE e.status = 'active'
  AND e.next_stage_at IS NOT NULL
  AND e.next_stage_at <= now()
ORDER BY e.next_stage_at ASC
LIMIT %s
"""

ADVANCE_SQL = """
UPDATE finding_escalation_state
SET stage_index = %s,
    next_stage_at = %s,
    status = %s,
    stopped_reason = %s,
    updated_at = now()
WHERE finding_id = %s AND status = 'active'
"""

STOP_TRIAGED_SQL = """
UPDATE finding_escalation_state e
SET status = 'stopped',
    stopped_reason = f.status,
    next_stage_at = NULL,
    updated_at = now()
FROM findings f
WHERE e.finding_id = f.finding_id
  AND e.status = 'active'
  AND f.status <> 'new'
RETURNING e.finding_id
"""

DUE_LIMIT = 1000


def _log_json(payload: dict) -> None:
    print(json.dumps(payload), file=sys.stderr, flush=True)


def next_stage_at(
    policy: EscalationPolicy, completed_stage_index: int, *, now: datetime | None = None
) -> datetime | None:
    """When the stage after ``completed_stage_index`` should fire."""
    nxt = completed_stage_index + 1
    if nxt >= len(policy.stages):
        return None
    now = now or datetime.now(timezone.utc)
    delay = policy.stages[nxt].after_seconds
    return now + timedelta(seconds=delay)


def enroll(
    conn: Any,
    policy: EscalationPolicy,
    findings: Iterable[dict],
    *,
    now: datetime | None = None,
) -> int:
    """Write escalation state for newly inserted findings. Returns enroll count."""
    now = now or datetime.now(timezone.utc)
    # Stage 0 already delivered by caller; schedule stage 1 if present.
    nxt = next_stage_at(policy, 0, now=now)
    status = "active" if nxt is not None else "exhausted"
    count = 0
    with conn.cursor() as cur:
        for finding in findings:
            cur.execute(
                ENROLL_SQL,
                (
                    finding["finding_id"],
                    policy.id,
                    0,
                    nxt if status == "active" else None,
                    status,
                ),
            )
            if cur.rowcount:
                count += 1
    if count:
        conn.commit()
        _log_json({
            "event": "guardrail.escalation.enroll",
            "policy_id": policy.id,
            "enrolled": count,
            "next_stage_at": nxt.isoformat() if nxt else None,
        })
    return count


def stop_triaged(conn: Any) -> int:
    """Cancel active escalations whose findings are no longer open. Never raises."""
    try:
        with conn.cursor() as cur:
            cur.execute(STOP_TRIAGED_SQL)
            stopped = cur.rowcount or 0
        if stopped:
            conn.commit()
            _log_json({
                "event": "guardrail.escalation.stopped",
                "stopped": stopped,
                "reason": "finding_left_new",
            })
        else:
            conn.rollback()
        return stopped
    except Exception as exc:  # noqa: BLE001 — housekeeping must not stop evaluation
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        _log_json({
            "event": "guardrail.escalation.stop.error",
            "error_type": type(exc).__name__,
            "error": str(exc),
        })
        return 0


def _row_to_finding(row: Any) -> dict:
    (
        finding_id, _policy_id, _stage_index,
        ts, rule_id, severity, title, subject, evidence,
        policy_hash, decision, _finding_status,
    ) = row
    if isinstance(subject, str):
        subject = json.loads(subject)
    if isinstance(evidence, str):
        evidence = json.loads(evidence)
    return {
        "finding_id": str(finding_id),
        "ts": ts,
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "subject": subject or {},
        "evidence": evidence or {},
        "policy_hash": policy_hash,
        "decision": decision,
    }


def advance_due(
    conn: Any,
    notifiers: list,
    policies: Sequence[EscalationPolicy],
    deliver_batch,
    summary: Any,
    *,
    now: datetime | None = None,
    limit: int = DUE_LIMIT,
) -> int:
    """Fire due escalation stages. Returns number of findings advanced.

    ``deliver_batch`` is injected (``dbrunner.deliver_batch``) to keep a
    single delivery/audit path. Never raises into the evaluate-db run.
    """
    if not policies:
        return 0
    now = now or datetime.now(timezone.utc)
    by_id = {p.id: p for p in policies}
    advanced = 0
    try:
        with conn.cursor() as cur:
            cur.execute(DUE_SQL, (limit,))
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        _log_json({
            "event": "guardrail.escalation.advance.error",
            "error_type": type(exc).__name__,
            "error": str(exc),
        })
        return 0

    if not rows:
        return 0

    for row in rows:
        finding_id = str(row[0])
        policy_id = row[1]
        stage_index = int(row[2])
        finding_status = row[11]
        policy = by_id.get(policy_id)
        if policy is None:
            # Policy removed from ruleset — stop the ladder.
            _mark(conn, finding_id, stage_index, None, "stopped", "policy_removed")
            continue
        if finding_status not in OPEN_STATUSES:
            _mark(conn, finding_id, stage_index, None, "stopped", finding_status)
            continue

        next_index = stage_index + 1
        if next_index >= len(policy.stages):
            _mark(conn, finding_id, stage_index, None, "exhausted", None)
            continue

        selected = _notifiers_for_stage(
            notifiers, policy, stage_index=next_index, include_non_stage=False
        )
        finding = _row_to_finding(row)
        if selected:
            try:
                deliver_batch(conn, selected, [finding], summary)
            except Exception as exc:  # noqa: BLE001 — deliver_batch already swallows; belt
                _log_json({
                    "event": "guardrail.escalation.deliver.error",
                    "finding_id": finding_id,
                    "policy_id": policy_id,
                    "stage_index": next_index,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                })

        nxt = next_stage_at(policy, next_index, now=now)
        status = "active" if nxt is not None else "exhausted"
        _mark(conn, finding_id, next_index, nxt if status == "active" else None, status, None)
        advanced += 1
        _log_json({
            "event": "guardrail.escalation.stage",
            "finding_id": finding_id,
            "policy_id": policy_id,
            "stage_index": next_index,
            "destinations": list(policy.stage_destinations(next_index)),
            "next_stage_at": nxt.isoformat() if nxt else None,
            "status": status,
        })

    if hasattr(summary, "escalations_advanced"):
        summary.escalations_advanced += advanced
    return advanced


def _mark(
    conn: Any,
    finding_id: str,
    stage_index: int,
    next_at: datetime | None,
    status: str,
    stopped_reason: str | None,
) -> None:
    try:
        with conn.cursor() as cur:
            cur.execute(
                ADVANCE_SQL,
                (stage_index, next_at, status, stopped_reason, finding_id),
            )
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        _log_json({
            "event": "guardrail.escalation.mark.error",
            "finding_id": finding_id,
            "error_type": type(exc).__name__,
            "error": str(exc),
        })


def policies_from_ruleset(ruleset: Any) -> list[EscalationPolicy]:
    """Load policies from a ruleset; empty list when unset. Raises on bad shape."""
    alerts = (ruleset.settings or {}).get("alerts") if ruleset else None
    return parse_escalation_policies(alerts)
