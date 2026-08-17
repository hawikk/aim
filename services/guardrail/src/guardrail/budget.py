"""Per-team token/cost budget evaluation (AIM-383 / AIM-326).

Reads ``team_budgets`` + current-period usage from ``events``, and emits
guardrail findings at warn (default 80%) and critical (default 100%) of each
configured limit. Edge-triggered via ``budget_alert_state`` so a team that
stays over budget does not re-page every poll cycle.

Degrades gracefully:
  * Missing tables (migration not applied) → no-op, logged once per run.
  * Empty ``team_budgets`` → no-op (no budgets configured).
  * Events with NULL team are excluded from team budgets.
  * Cost uses ``COALESCE(cost_estimate_usd, 0)`` — estimates only; see
    ``docs/cost-attribution-accuracy.md``.

Findings use rule ids:
  * ``team-budget-tokens-warn`` / ``team-budget-tokens-critical``
  * ``team-budget-cost-warn`` / ``team-budget-cost-critical``
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .engine import DECISION, FINDING_SCHEMA

BUDGET_NS = uuid.UUID("a3830000-0000-4000-8000-000000000383")

RULE_META = {
    ("tokens", "warn"): {
        "rule_id": "team-budget-tokens-warn",
        "severity": "medium",
        "title": "Team token budget at warning threshold",
    },
    ("tokens", "critical"): {
        "rule_id": "team-budget-tokens-critical",
        "severity": "high",
        "title": "Team token budget at critical threshold",
    },
    ("cost_usd", "warn"): {
        "rule_id": "team-budget-cost-warn",
        "severity": "medium",
        "title": "Team cost budget at warning threshold",
    },
    ("cost_usd", "critical"): {
        "rule_id": "team-budget-cost-critical",
        "severity": "high",
        "title": "Team cost budget at critical threshold",
    },
}


@dataclass
class BudgetRunSummary:
    budgets: int = 0
    evaluated: int = 0
    findings: int = 0
    findings_inserted: int = 0
    skipped_missing_table: bool = False
    errors: list[str] = field(default_factory=list)


def _period_bounds(period: str, now: datetime) -> tuple[datetime, datetime]:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if period == "rolling_30d":
        return now - timedelta(days=30), now
    start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    return start, now


def _pct(used: float, limit: float) -> float:
    if limit <= 0:
        return 0.0
    return (used / limit) * 100.0


def _fetch_budgets(conn: Any) -> list[dict] | None:
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT team, period, token_budget, cost_budget_usd,
                       warn_pct, critical_pct
                FROM team_budgets
                WHERE enabled = true
                ORDER BY team
                """
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).lower()
        if "team_budgets" in msg or "does not exist" in msg or "undefinedtable" in msg:
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                pass
            return None
        raise


def _usage_for_team(
    conn: Any, team: str, period_start: datetime, period_end: datetime
) -> tuple[float, float]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
              COALESCE(SUM(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)), 0) AS tokens,
              COALESCE(SUM(COALESCE(cost_estimate_usd, 0)), 0) AS cost_usd
            FROM events
            WHERE team = %s
              AND ts >= %s AND ts < %s
              AND tool <> 'genai_app'
            """,
            (team, period_start, period_end),
        )
        row = cur.fetchone()
        return float(row[0] or 0), float(row[1] or 0)


def _already_fired(
    conn: Any, team: str, metric: str, threshold_pct: float, period_start: datetime
) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT 1 FROM budget_alert_state
            WHERE team = %s AND metric = %s
              AND threshold_pct = %s AND period_start = %s
            """,
            (team, metric, threshold_pct, period_start),
        )
        return cur.fetchone() is not None


def _record_fired(
    conn: Any,
    team: str,
    metric: str,
    threshold_pct: float,
    period_start: datetime,
    finding_id: str,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO budget_alert_state
              (team, metric, threshold_pct, period_start, finding_id)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (team, metric, threshold_pct, period_start) DO NOTHING
            """,
            (team, metric, threshold_pct, period_start, finding_id),
        )


def _build_finding(
    *,
    rule_id: str,
    severity: str,
    title: str,
    team: str,
    metric: str,
    used: float,
    limit: float,
    pct_used: float,
    threshold_pct: float,
    period: str,
    period_start: datetime,
    period_end: datetime,
    policy_hash: str,
    ruleset_version: int | str,
    now: datetime,
) -> dict:
    finding_id = str(uuid.uuid4())
    synthetic_event_id = str(
        uuid.uuid5(
            BUDGET_NS,
            f"{rule_id}:{team}:{metric}:{threshold_pct}:{period_start.isoformat()}",
        )
    )
    evidence = {
        "event_ids": [synthetic_event_id],
        "detail": {
            "metric": metric,
            "used": used,
            "limit": limit,
            "pct_used": round(pct_used, 2),
            "threshold_pct": float(threshold_pct),
            "period": period,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "cost_accuracy": "estimate" if metric == "cost_usd" else "measured_when_reported",
        },
        "group_by": {"team": team},
        "context": {"team": team, "source": "budget_evaluator"},
    }
    return {
        "schema": FINDING_SCHEMA,
        "finding_id": finding_id,
        "rule_id": rule_id,
        "ruleset_version": ruleset_version,
        "policy_hash": policy_hash,
        "severity": severity,
        "title": title,
        "decision": DECISION,
        "ts": now.isoformat(),
        "subject": {"user_ref": None, "host_ref": None, "team": team},
        "evidence": evidence,
    }


def evaluate_team_budgets(
    conn: Any,
    *,
    policy_hash: str = "budget-evaluator",
    ruleset_version: int | str = 1,
    now: datetime | None = None,
) -> tuple[list[dict], BudgetRunSummary]:
    """Evaluate all enabled team budgets. Returns (new_findings, summary)."""
    summary = BudgetRunSummary()
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    try:
        budgets = _fetch_budgets(conn)
    except Exception as exc:  # noqa: BLE001
        summary.errors.append(f"fetch budgets failed: {exc}")
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        return [], summary

    if budgets is None:
        summary.skipped_missing_table = True
        return [], summary

    summary.budgets = len(budgets)
    findings: list[dict] = []

    for b in budgets:
        team = b["team"]
        period = b["period"] or "calendar_month"
        warn_pct = float(b["warn_pct"] or 80)
        crit_pct = float(b["critical_pct"] or 100)
        period_start, period_end = _period_bounds(period, now)

        try:
            tokens, cost_usd = _usage_for_team(conn, team, period_start, period_end)
        except Exception as exc:  # noqa: BLE001
            summary.errors.append(f"usage for team {team!r} failed: {exc}")
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                pass
            continue

        summary.evaluated += 1
        checks: list[tuple[str, float, float | None]] = []
        if b.get("token_budget") is not None:
            checks.append(("tokens", tokens, float(b["token_budget"])))
        if b.get("cost_budget_usd") is not None:
            checks.append(("cost_usd", cost_usd, float(b["cost_budget_usd"])))

        for metric, used, limit in checks:
            if limit is None or limit <= 0:
                continue
            pct_used = _pct(used, limit)
            for level, thr in (("critical", crit_pct), ("warn", warn_pct)):
                if pct_used < thr:
                    continue
                meta = RULE_META[(metric, level)]
                try:
                    if _already_fired(conn, team, metric, thr, period_start):
                        continue
                except Exception as exc:  # noqa: BLE001
                    summary.errors.append(f"alert state read failed: {exc}")
                    try:
                        conn.rollback()
                    except Exception:  # noqa: BLE001
                        pass
                    continue

                findings.append(
                    _build_finding(
                        rule_id=meta["rule_id"],
                        severity=meta["severity"],
                        title=meta["title"],
                        team=team,
                        metric=metric,
                        used=used,
                        limit=limit,
                        pct_used=pct_used,
                        threshold_pct=thr,
                        period=period,
                        period_start=period_start,
                        period_end=period_end,
                        policy_hash=policy_hash,
                        ruleset_version=ruleset_version,
                        now=now,
                    )
                )
                summary.findings += 1

    return findings, summary


def apply_budget_findings(
    conn: Any,
    findings: list[dict],
    insert_finding_fn,
) -> list[dict]:
    """Insert budget findings and record alert state. Returns inserted findings."""
    inserted: list[dict] = []
    for finding in findings:
        detail = (finding.get("evidence") or {}).get("detail") or {}
        group = (finding.get("evidence") or {}).get("group_by") or {}
        team = group.get("team") or (finding.get("subject") or {}).get("team")
        metric = detail.get("metric")
        thr = detail.get("threshold_pct")
        period_start_raw = detail.get("period_start")
        if not (team and metric and thr is not None and period_start_raw):
            continue
        period_start = datetime.fromisoformat(period_start_raw.replace("Z", "+00:00"))
        if insert_finding_fn(conn, finding):
            inserted.append(finding)
            try:
                _record_fired(
                    conn, team, metric, float(thr), period_start, finding["finding_id"]
                )
            except Exception:  # noqa: BLE001
                try:
                    conn.rollback()
                except Exception:  # noqa: BLE001
                    pass
    return inserted
