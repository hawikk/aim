"""Post-ingest evaluation runner (AIM-32).

Evaluates stored events from the ingest Postgres database against the policy
ruleset and writes guardrail.finding/v1 rows into the findings table.

Exactly-once: evaluated_events records every event_id that has been through
the engine; findings are inserted ON CONFLICT (rule_id, event_id) DO NOTHING,
so re-running is always safe. Threshold-rule sliding windows are in-memory
per run (same as the streaming CLI) — events are fed oldest-first.

Alert delivery (AIM-76): findings that were newly inserted in a batch (the
conflict no-ops excluded — insert_finding's return value is the edge trigger)
are forwarded to the configured notifiers (see notify.py) after that batch's
commit. A delivery failure never rolls back the finding insert and never
crashes the run: it is logged as guardrail.alert.error and recorded in
finding_deliveries (one row per finding per destination) for audit.

Privacy: events are reconstructed from the stored canonical payload, which is
metadata-only by ingest schema contract; findings carry detector names and
pseudonyms, never content. Alert payloads are built from the same
metadata-only finding fields.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

import psycopg

from . import notify
from .engine import Engine
from .rules import Ruleset, load_ruleset

DEFAULT_BATCH_SIZE = 500

FINDING_INSERT = """
INSERT INTO findings
  (finding_id, ts, rule_id, severity, title, subject, evidence, policy_hash, decision, event_id)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (rule_id, event_id) DO NOTHING
"""

UNEVALUATED_QUERY = """
SELECT e.event_id, e.payload, e.team, e.user_pseudonym
FROM events e
LEFT JOIN evaluated_events x ON x.event_id = e.event_id
WHERE x.event_id IS NULL
ORDER BY e.ts ASC, e.event_id
LIMIT %s
"""

EVALUATED_INSERT = """
INSERT INTO evaluated_events (event_id) VALUES (%s)
ON CONFLICT (event_id) DO NOTHING
"""

# AIM-76: one row per finding per destination, recording whether the alert
# reached the receiver. UNIQUE (finding_id, destination) keeps re-runs safe.
#
# AIM-158 made the row upgradable: the bus sweeper re-publishes findings that
# committed but never reached the bus, so a 'failed' row must be able to
# become 'delivered'. The WHERE clause makes 'delivered' terminal — a later
# failure can never downgrade a delivery that actually happened.
DELIVERY_INSERT = """
INSERT INTO finding_deliveries
  (finding_id, destination, status, attempts, http_status, error, delivered_at)
VALUES (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (finding_id, destination) DO UPDATE SET
  status       = EXCLUDED.status,
  attempts     = finding_deliveries.attempts + EXCLUDED.attempts,
  http_status  = EXCLUDED.http_status,
  error        = EXCLUDED.error,
  delivered_at = COALESCE(EXCLUDED.delivered_at, finding_deliveries.delivered_at)
WHERE finding_deliveries.status <> 'delivered'
"""

# AIM-158 (D3.1 §4.5, §12 item 6): findings that committed but never reached
# a destination. `deliver_batch` only ever sees findings inserted in the
# current batch, so without this a receiver outage during one guardrail cycle
# would drop those alerts permanently. Ordered oldest-first so a replaying
# consumer sees them in detection order.
#
# AIM-324: the attempt cap (%s, nullable) bounds re-drive. Destinations that
# declare a sweep_attempt_cap (the SIEM exporters) stop being picked up once
# the accumulated attempts reach it — the sweeper dead-letters those rows
# instead (DEAD_LETTER_UPDATE). NULL means uncapped (the bus, whose redrive
# is bounded by the lookback window rather than an attempt count).
UNDELIVERED_QUERY = """
SELECT f.finding_id, f.ts, f.rule_id, f.severity, f.title, f.subject, f.evidence,
       f.policy_hash, f.decision
FROM findings f
LEFT JOIN finding_deliveries d
  ON d.finding_id = f.finding_id AND d.destination = %s
WHERE (d.finding_id IS NULL
       OR (d.status = 'failed' AND (%s::int IS NULL OR d.attempts < %s::int)))
  AND f.ts > now() - %s::interval
ORDER BY f.ts ASC
LIMIT %s
"""

# AIM-324: failed -> dead once the accumulated attempts reach the
# destination's cap. Terminal, but operator-reversible (delete the 'dead'
# rows and the anti-join picks the findings up again) — the same trade
# 'rejected' made in 016, for the same reason: an endlessly-retried row
# crowds genuinely retryable findings out of the sweep window.
DEAD_LETTER_UPDATE = """
UPDATE finding_deliveries
SET status = 'dead'
WHERE destination = %s AND status = 'failed' AND attempts >= %s
RETURNING finding_id
"""

# AIM-324: visible lag. Per destination: how many findings within the sweep
# lookback are still pending (never delivered or failed-and-retryable), how
# many are dead-lettered, and the age of the oldest pending finding — the
# numbers a SOC watches to know "the SIEM is behind" before alerts go stale.
LAG_QUERY = """
SELECT
  count(*) FILTER (WHERE d.finding_id IS NULL OR d.status = 'failed') AS pending,
  count(*) FILTER (WHERE d.status = 'dead') AS dead,
  min(f.ts) FILTER (WHERE d.finding_id IS NULL OR d.status = 'failed') AS oldest_pending_ts
FROM findings f
LEFT JOIN finding_deliveries d
  ON d.finding_id = f.finding_id AND d.destination = %s
WHERE f.ts > now() - %s::interval
"""

# Bounds one sweep so a long outage cannot turn the next run into an
# unbounded republish storm; the remainder is picked up by the run after it.
SWEEP_LIMIT = 5000

# The sweep only looks back as far as the bus keeps entries (D3.1 §5). Two
# reasons, and the second is the one that bites: republishing a finding older
# than the retention window puts an alert on the bus that the next trim
# deletes, which is pure churn; and without a bound, the first run after
# ALERT_BUS_URL is switched on treats the entire findings archive as
# undelivered and replays months of history onto a fresh inbox, evicting the
# live alerts an analyst is actually looking at.
SWEEP_LOOKBACK = "30 days"


@dataclass
class RunSummary:
    events: int = 0
    findings: int = 0
    findings_inserted: int = 0
    batches: int = 0
    alerts_delivered: int = 0
    alerts_failed: int = 0
    alerts_swept: int = 0
    # Findings dead-lettered this run (failed -> dead at the destination's
    # attempt cap, AIM-324). Terminal, operator-reversible — see migration 019.
    alerts_dead_lettered: int = 0
    # Findings whose alert could not be built validly. Terminal, not pending —
    # counted separately so "we published nothing" and "we could not build
    # anything publishable" are distinguishable in the run log.
    alerts_rejected: int = 0
    # AIM-383: team budget evaluator (0 when no budgets / migration missing).
    budget_evaluated: int = 0
    budget_findings_inserted: int = 0
    # AIM-699: multi-stage escalation advances this run.
    escalations_advanced: int = 0
    escalations_enrolled: int = 0
    escalations_stopped: int = 0


def row_to_event(row: Any) -> dict:
    """Reconstruct the canonical event dict from an events table row.

    The ingest service stores the validated AIM-18 event verbatim in the
    payload JSONB column, so the engine sees exactly what the collector sent.

    Team / user_pseudonym are stamped at ingest by identity enrichment
    (AIM-49) as columns, not collector payload fields. Merge them so
    team-scoped budget and model-allowlist rules can group/match (AIM-383).
    """
    if len(row) >= 4:
        event_id, payload, team, user_pseudonym = row[0], row[1], row[2], row[3]
    else:
        event_id, payload = row[0], row[1]
        team = user_pseudonym = None
    if isinstance(payload, str):
        payload = json.loads(payload)
    event = dict(payload)
    event.setdefault("event_id", str(event_id))
    if team is not None:
        event["team"] = team
    if user_pseudonym is not None:
        event["user_pseudonym"] = user_pseudonym
    return event


def _finding_row(finding: dict) -> tuple:
    evidence = finding.get("evidence") or {}
    event_ids = evidence.get("event_ids") or []
    return (
        finding["finding_id"],
        finding["ts"],
        finding["rule_id"],
        finding["severity"],
        finding["title"],
        json.dumps(finding.get("subject") or {}),
        json.dumps(evidence),
        finding["policy_hash"],
        finding["decision"],
        event_ids[0] if event_ids else None,
    )


def fetch_unevaluated(conn: Any, batch_size: int) -> list:
    with conn.cursor() as cur:
        cur.execute(UNEVALUATED_QUERY, (batch_size,))
        return cur.fetchall()


def insert_finding(conn: Any, finding: dict) -> bool:
    """Insert one finding. Returns True if a new row was written."""
    with conn.cursor() as cur:
        cur.execute(FINDING_INSERT, _finding_row(finding))
        return cur.rowcount > 0


def mark_evaluated(conn: Any, event_ids: Iterable[str]) -> None:
    with conn.cursor() as cur:
        for event_id in event_ids:
            cur.execute(EVALUATED_INSERT, (event_id,))


def _log_json(payload: dict) -> None:
    """Same JSON-to-stderr style as poller._log."""
    print(json.dumps(payload), file=sys.stderr, flush=True)


def record_deliveries(
    conn: Any,
    finding_ids: Iterable[str],
    destination: str,
    status: str,
    *,
    attempts: int,
    http_status: int | None,
    error: str | None,
) -> None:
    """Persist one finding_deliveries row per finding for a destination."""
    delivered_at = datetime.now(timezone.utc) if status == "delivered" else None
    with conn.cursor() as cur:
        for finding_id in finding_ids:
            cur.execute(DELIVERY_INSERT, (
                finding_id, destination, status, attempts, http_status, error, delivered_at,
            ))


def deliver_batch(conn: Any, notifiers: list, findings: list[dict], summary: RunSummary) -> None:
    """Forward one batch of newly inserted findings through every notifier.

    The finding rows are already committed; nothing here may roll them back
    or crash the run. Failures are logged as guardrail.alert.error and
    recorded as status='failed' rows so non-delivery is auditable.
    """
    for notifier in notifiers:
        destination = notifier.destination
        try:
            result = notifier.deliver(findings)
        except Exception as exc:  # noqa: BLE001 — delivery must never fail the run
            _log_json({
                "event": "guardrail.alert.error",
                "destination": destination,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "findings": len(findings),
            })
            finding_ids = getattr(exc, "finding_ids", None) or [f["finding_id"] for f in findings]
            # A publisher-side rejection (D3.1 §12 item 21) arrives here as an
            # exception like any other delivery failure, but it is terminal
            # rather than retryable: the mapping produced an alert the contract
            # forbids, and re-running it changes nothing. Recording it as
            # 'rejected' keeps the finding out of the sweeper's anti-join —
            # without a row it is re-mapped, re-rejected and re-logged on every
            # run, eventually filling the whole SWEEP_LIMIT window with
            # findings that can never succeed and starving the ones that could.
            rejection = getattr(exc, "terminal", False)
            status, attempts, http_status, error = (
                "rejected" if rejection else "failed",
                getattr(exc, "attempts", 0), getattr(exc, "http_status", None), str(exc),
            )
            if rejection:
                summary.alerts_rejected += len(finding_ids)
                # Neighbours that DID reach the stream in the same batch. They
                # are delivered and must be recorded as such, or the next sweep
                # republishes alerts this run already published.
                delivered = [fid for fid in getattr(exc, "delivered", ()) or () if fid]
                if delivered:
                    summary.alerts_delivered += len(delivered)
                    _record_or_log(
                        conn, delivered, destination, "delivered",
                        attempts=1, http_status=None, error=None,
                    )
            else:
                summary.alerts_failed += len(finding_ids)
        else:
            finding_ids = result.finding_ids
            status, attempts, http_status, error = (
                "delivered", result.attempts, result.http_status, None,
            )
            summary.alerts_delivered += len(finding_ids)
        if not finding_ids:
            continue
        _record_or_log(
            conn, finding_ids, destination, status,
            attempts=attempts, http_status=http_status, error=error,
        )


def _record_or_log(
    conn: Any, finding_ids: list, destination: str, status: str,
    *, attempts: int, http_status: int | None, error: str | None,
) -> None:
    """Write delivery rows; an audit-write failure must not fail the run."""
    try:
        record_deliveries(
            conn, finding_ids, destination, status,
            attempts=attempts, http_status=http_status, error=error,
        )
        conn.commit()
    except Exception as exc:  # noqa: BLE001 — audit write must not fail the run either
        conn.rollback()
        _log_json({
            "event": "guardrail.alert.error",
            "destination": destination,
            "error_type": type(exc).__name__,
            "error": f"recording delivery status failed: {exc}",
            "findings": len(finding_ids),
        })


def row_to_finding(row: Any) -> dict:
    """Rebuild a finding dict from a findings row, for republishing.

    The stored columns are exactly what the publisher maps from, so a swept
    finding produces a byte-identical alert to the one the original run would
    have published — the same alert_id, so a consumer that did receive it
    dedupes on redelivery (§7.2) rather than showing it twice.

    ``ts`` is handed over as psycopg returns it (an aware datetime for a
    TIMESTAMPTZ column) and normalized by the publisher's own to_utc_second.
    Formatting it here with a hand-rolled strftime was how the two paths
    diverged: ``"%Y-...%SZ"`` stamps a literal Z onto whatever wall clock the
    session timezone produced, so on a non-UTC session a swept alert published
    a time that was valid, plausible, and wrong.
    """
    finding_id, ts, rule_id, severity, title, subject, evidence, policy_hash, decision = row
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


def sweep_undelivered(conn: Any, notifiers: list, summary: RunSummary) -> None:
    """Re-publish findings that committed but never reached a destination.

    D3.1 §4.5: the outbox pattern is only at-least-once end to end if
    something re-drives the gap between "the finding committed" and "the alert
    was published". `deliver_batch` cannot — it only sees the current batch —
    so a bus outage lasting one guardrail cycle would silently truncate the
    bus. That is the failure this function exists to prevent, and it is a
    routine restart, not an incident.

    Only destinations that opt in are swept: re-driving an HTTPS webhook or
    the Sentinel forwarder would re-page a SOC for old findings, whereas the
    bus is a replayable log whose consumers are required to be idempotent on
    alert_id (§7.2). AIM-324 extends the opt-in to the SIEM exporters
    (splunk_hec, syslog_cef): a SIEM intake is a dedup-able log, not a pager —
    the stable finding id (OCSF finding_info.uid / CEF externalId) is the
    receiver's dedupe key — and the charter requires at-least-once export.
    SIEM re-drive is bounded: at sweep_attempt_cap accumulated attempts the
    row is dead-lettered (status='dead') and left for an operator to replay.

    Never raises. This runs *before* evaluation, so an exception here — an
    unapplied migration, a malformed evidence column, a DB blip on the
    anti-join — would stop the engine from evaluating any new events at all.
    Republishing old alerts must never cost detection of new ones.
    """
    for notifier in notifiers:
        if not getattr(notifier, "sweeps_undelivered", False):
            continue
        attempt_cap = getattr(notifier, "sweep_attempt_cap", None)
        try:
            with conn.cursor() as cur:
                if attempt_cap is not None:
                    # Dead-letter first so an at-cap row is neither re-driven
                    # below nor counted as pending in this run's lag report.
                    cur.execute(DEAD_LETTER_UPDATE, (notifier.destination, attempt_cap))
                    dead_ids = [str(row[0]) for row in cur.fetchall()]
                    if dead_ids:
                        conn.commit()
                        summary.alerts_dead_lettered += len(dead_ids)
                        _log_json({
                            "event": "guardrail.alert.deadletter",
                            "destination": notifier.destination,
                            "dead_lettered": len(dead_ids),
                            "finding_ids": dead_ids,
                        })
                cur.execute(
                    UNDELIVERED_QUERY,
                    (notifier.destination, attempt_cap, attempt_cap, SWEEP_LOOKBACK, SWEEP_LIMIT),
                )
                rows = cur.fetchall()
            findings = [row_to_finding(row) for row in rows]
        except Exception as exc:  # noqa: BLE001 — housekeeping must not stop evaluation
            conn.rollback()
            _log_json({
                "event": "guardrail.alert.sweep.error",
                "destination": notifier.destination,
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
            continue
        if not findings:
            continue
        _log_json({
            "event": "guardrail.alert.sweep",
            "destination": notifier.destination,
            "undelivered": len(findings),
        })
        summary.alerts_swept += len(findings)
        deliver_batch(conn, [notifier], findings, summary)


def delivery_lag(conn: Any, destinations: Iterable[str]) -> list[dict]:
    """Per-destination delivery lag over the sweep lookback window (AIM-324).

    Returns one dict per destination: ``pending`` (never delivered or
    failed-and-retryable), ``dead`` (dead-lettered), and
    ``oldest_pending_age_seconds`` (age of the oldest pending finding; None
    when nothing is pending). Read-only; raises on DB error — callers wrap.
    """
    report: list[dict] = []
    now = datetime.now(timezone.utc)
    for destination in destinations:
        with conn.cursor() as cur:
            cur.execute(LAG_QUERY, (destination, SWEEP_LOOKBACK))
            pending, dead, oldest_ts = cur.fetchone()
        age: float | None = None
        if oldest_ts is not None:
            if oldest_ts.tzinfo is None:
                oldest_ts = oldest_ts.replace(tzinfo=timezone.utc)
            age = round((now - oldest_ts).total_seconds(), 3)
        report.append({
            "destination": destination,
            "pending": pending,
            "dead": dead,
            "oldest_pending_age_seconds": age,
        })
    return report


def log_delivery_lag(conn: Any, notifiers: list) -> None:
    """Emit the guardrail.alert.lag run log line. Never raises: a lag-report
    failure must not cost the run its evaluation or its deliveries."""
    destinations = [n.destination for n in notifiers]
    if not destinations:
        return
    try:
        report = delivery_lag(conn, destinations)
        conn.rollback()  # read-only tx; leave nothing open for the next run
        _log_json({"event": "guardrail.alert.lag", "destinations": report})
    except Exception as exc:  # noqa: BLE001 — observability must not stop detection
        conn.rollback()
        _log_json({
            "event": "guardrail.alert.lag.error",
            "error_type": type(exc).__name__,
            "error": str(exc),
        })


def notifiers_from_ruleset(ruleset: Ruleset) -> list:
    """AIM-94: alert destinations come from the ruleset's ``settings.alerts``
    when the policy defines them; otherwise fall back to the legacy env
    config (AIM-76). Logs the chosen source and enabled destinations (never
    secrets)."""
    alerts = ruleset.settings.get("alerts")
    if alerts is not None:
        source, notifiers = "policy", notify.notifiers_from_config(alerts)
    else:
        source, notifiers = "env", notify.notifiers_from_env()
    _log_json({
        "event": "guardrail.alert.config",
        "source": source,
        "destinations": [n.destination for n in notifiers],
    })
    return notifiers



def deliver_findings(
    conn: Any,
    notifiers: list,
    findings: list[dict],
    summary: RunSummary,
    *,
    policies: list | None = None,
) -> None:
    """Forward findings with optional multi-stage escalation (AIM-699).

    Without policies, identical to ``deliver_batch`` (all notifiers). With
    policies, stage-0 destinations fire now; later stages are enrolled and
    advanced by ``advance_escalations``.
    """
    if not findings or not notifiers:
        return
    if not policies:
        deliver_batch(conn, notifiers, findings, summary)
        return
    from . import escalation as escalation_mod

    groups, enrollments = escalation_mod.partition_notifiers_for_findings(
        notifiers, findings, policies
    )
    for selected, group in groups:
        if selected and group:
            deliver_batch(conn, selected, group, summary)
    for policy, group in enrollments:
        enrolled = escalation_mod.enroll(conn, policy, group)
        summary.escalations_enrolled += enrolled


def advance_escalations(
    conn: Any,
    notifiers: list,
    policies: list,
    summary: RunSummary,
) -> None:
    """Stop triaged ladders, then fire due stages. Never raises."""
    if not policies:
        return
    from . import escalation as escalation_mod

    stopped = escalation_mod.stop_triaged(conn)
    summary.escalations_stopped += stopped
    advanced = escalation_mod.advance_due(
        conn, notifiers, policies, deliver_batch, summary
    )
    # advanced already counted on summary inside advance_due when attribute exists


def run(
    conn: Any,
    rules_path: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
    notifiers: Iterable[Any] = (),
    ruleset: Ruleset | None = None,
    policies: list | None = None,
) -> RunSummary:
    """Evaluate every unevaluated event and store findings. Idempotent.

    `notifiers` (see notify.py) receive each batch of newly inserted findings
    after that batch commits (AIM-76); the default empty tuple disables
    delivery. `ruleset` may be passed pre-loaded (run_dsn does, so alert
    config and evaluation share one load/hash); otherwise it is loaded from
    `rules_path`. `policies` are AIM-699 escalation policies; when omitted
    they are loaded from the ruleset's settings.alerts.
    """
    loaded = ruleset or load_ruleset(rules_path)
    engine = Engine(loaded)
    notifiers = list(notifiers)
    if policies is None:
        from . import escalation as escalation_mod
        try:
            policies = escalation_mod.policies_from_ruleset(loaded)
        except Exception as exc:  # noqa: BLE001 — bad policy must not kill evaluate-db
            _log_json({
                "event": "guardrail.escalation.config.error",
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
            policies = []
    else:
        policies = list(policies)
    summary = RunSummary()
    # Before evaluating anything new, close the gap left by a previous run
    # that committed findings it could not publish (D3.1 §4.5).
    if notifiers:
        sweep_undelivered(conn, notifiers, summary)
        # AIM-699: fire due escalation stages (Slack → PagerDuty timers).
        advance_escalations(conn, notifiers, policies, summary)
    while True:
        rows = fetch_unevaluated(conn, batch_size)
        if not rows:
            break
        summary.batches += 1
        new_findings: list[dict] = []
        for row in rows:
            event = row_to_event(row)
            findings, _audit = engine.evaluate(event)
            summary.events += 1
            for finding in findings:
                summary.findings += 1
                if insert_finding(conn, finding):
                    summary.findings_inserted += 1
                    new_findings.append(finding)
        mark_evaluated(conn, [str(row[0]) for row in rows])
        conn.commit()
        if new_findings and notifiers:
            deliver_findings(conn, notifiers, new_findings, summary, policies=policies)

    # AIM-383: team budget thresholds (80/100%) after the event pass.
    # Missing tables or empty team_budgets → no-op (degrade open).
    _run_budget_evaluation(conn, engine, notifiers, summary, policies=policies)
    # AIM-575: App-LLM new-sources signal → SOC alert destinations.
    # First-ever proxy provider-API (host_ref, provider) inside lookback →
    # finding → existing webhook/Sentinel/Google Chat path.
    _run_new_source_evaluation(conn, engine, notifiers, summary, policies=policies)
    # AIM-738: catalogue completeness — new uncatalogued providers/models.
    _run_catalogue_drift_evaluation(conn, engine, notifiers, summary)
    if notifiers:
        # AIM-324: visible lag — one line per run with per-destination
        # pending/dead counts and the age of the oldest pending finding.
        log_delivery_lag(conn, notifiers)
    return summary


def _run_budget_evaluation(
    conn: Any, engine: Engine, notifiers: list, summary: RunSummary,
    *, policies: list | None = None,
) -> None:
    """Evaluate team budgets; never raise into the main evaluate-db run."""
    try:
        from . import budget as budget_mod

        findings, bsum = budget_mod.evaluate_team_budgets(
            conn,
            policy_hash=engine.ruleset.content_hash,
            ruleset_version=engine.ruleset.version,
        )
        summary.budget_evaluated = bsum.evaluated
        if bsum.skipped_missing_table:
            _log_json({
                "event": "guardrail.budget.skip",
                "reason": "team_budgets table missing (migration 019 not applied)",
            })
            return
        if bsum.errors:
            _log_json({
                "event": "guardrail.budget.error",
                "errors": bsum.errors[:5],
                "error_count": len(bsum.errors),
            })
        if not findings:
            _log_json({
                "event": "guardrail.budget.run",
                "budgets": bsum.budgets,
                "evaluated": bsum.evaluated,
                "findings": 0,
                "inserted": 0,
            })
            return
        inserted = budget_mod.apply_budget_findings(conn, findings, insert_finding)
        summary.budget_findings_inserted = len(inserted)
        summary.findings += len(findings)
        summary.findings_inserted += len(inserted)
        conn.commit()
        if inserted and notifiers:
            deliver_findings(conn, notifiers, inserted, summary, policies=policies or [])
        _log_json({
            "event": "guardrail.budget.run",
            "budgets": bsum.budgets,
            "evaluated": bsum.evaluated,
            "findings": len(findings),
            "inserted": len(inserted),
        })
    except Exception as exc:  # noqa: BLE001 — budget path must not kill evaluate-db
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        _log_json({
            "event": "guardrail.budget.error",
            "error_type": type(exc).__name__,
            "error": str(exc),
        })


def _run_new_source_evaluation(
    conn: Any, engine: Engine, notifiers: list, summary: RunSummary,
    *, policies: list | None = None,
) -> None:
    """Evaluate App-LLM new-sources signal; never raise into evaluate-db."""
    try:
        from . import new_sources as new_sources_mod

        findings, nsum = new_sources_mod.evaluate_new_sources(
            conn,
            policy_hash=engine.ruleset.content_hash,
            ruleset_version=engine.ruleset.version,
        )
        if nsum.skipped_missing_table:
            _log_json({
                "event": "guardrail.new_source.skip",
                "reason": "events table missing or unreadable",
            })
            return
        if nsum.errors:
            _log_json({
                "event": "guardrail.new_source.error",
                "errors": nsum.errors[:5],
                "error_count": len(nsum.errors),
            })
        if not findings:
            _log_json({
                "event": "guardrail.new_source.run",
                "candidates": nsum.candidates,
                "lookback_hours": nsum.lookback_hours,
                "providers": nsum.providers,
                "findings": 0,
                "inserted": 0,
            })
            return
        inserted = new_sources_mod.apply_new_source_findings(
            conn, findings, insert_finding
        )
        summary.findings += len(findings)
        summary.findings_inserted += len(inserted)
        conn.commit()
        if inserted and notifiers:
            deliver_findings(conn, notifiers, inserted, summary, policies=policies or [])
        _log_json({
            "event": "guardrail.new_source.run",
            "candidates": nsum.candidates,
            "lookback_hours": nsum.lookback_hours,
            "providers": nsum.providers,
            "findings": len(findings),
            "inserted": len(inserted),
        })
    except Exception as exc:  # noqa: BLE001 — new-source path must not kill evaluate-db
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        _log_json({
            "event": "guardrail.new_source.error",
            "error_type": type(exc).__name__,
            "error": str(exc),
        })


def _run_catalogue_drift_evaluation(
    conn: Any, engine: Engine, notifiers: list, summary: RunSummary
) -> None:
    """Evaluate uncatalogued providers/models (AIM-738); never raise into evaluate-db."""
    try:
        from . import catalogue_drift as drift_mod

        findings, dsum = drift_mod.evaluate_catalogue_drift(
            conn,
            policy_hash=engine.ruleset.content_hash,
            ruleset_version=engine.ruleset.version,
        )
        if dsum.skipped_missing_table:
            _log_json({
                "event": "guardrail.catalogue_drift.skip",
                "reason": "events table missing or unreadable",
            })
            return
        if dsum.errors:
            _log_json({
                "event": "guardrail.catalogue_drift.error",
                "errors": dsum.errors[:5],
                "error_count": len(dsum.errors),
            })
        if not findings:
            _log_json({
                "event": "guardrail.catalogue_drift.run",
                "new_providers": dsum.new_providers_candidates,
                "new_models": dsum.new_models_candidates,
                "lookback_hours": dsum.lookback_hours,
                "known_providers": dsum.known_providers,
                "known_models": dsum.known_models,
                "findings": 0,
                "inserted": 0,
            })
            return
        inserted = drift_mod.apply_drift_findings(conn, findings, insert_finding)
        summary.findings += len(findings)
        summary.findings_inserted += len(inserted)
        conn.commit()
        if inserted and notifiers:
            deliver_batch(conn, notifiers, inserted, summary)
        _log_json({
            "event": "guardrail.catalogue_drift.run",
            "new_providers": dsum.new_providers_candidates,
            "new_models": dsum.new_models_candidates,
            "lookback_hours": dsum.lookback_hours,
            "known_providers": dsum.known_providers,
            "known_models": dsum.known_models,
            "findings": len(findings),
            "inserted": len(inserted),
        })
    except Exception as exc:  # noqa: BLE001 — drift path must not kill evaluate-db
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        _log_json({
            "event": "guardrail.catalogue_drift.error",
            "error_type": type(exc).__name__,
            "error": str(exc),
        })


def run_dsn(
    dsn: str,
    rules_path: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
    notifiers: Iterable[Any] | None = None,
) -> RunSummary:
    """notifiers=None (the production default) builds them from the ruleset's
    settings.alerts when the policy defines them, else from env (AIM-76);
    pass an explicit list (empty to disable) in tests."""
    ruleset = load_ruleset(rules_path)
    if notifiers is None:
        notifiers = notifiers_from_ruleset(ruleset)
    with psycopg.connect(dsn) as conn:
        return run(conn, rules_path, batch_size, notifiers, ruleset=ruleset)


def dsn_from_env(env: dict | None = None) -> str:
    env = env if env is not None else os.environ
    dsn = env.get("DATABASE_URL")
    if not dsn:
        raise ValueError("DATABASE_URL is required (postgres://user:pass@host:5432/db)")
    return dsn
