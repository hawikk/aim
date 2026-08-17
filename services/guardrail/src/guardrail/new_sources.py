"""App-LLM new-source signal → guardrail finding.

Phase-1 App-LLM visibility surfaces ``newSources`` on the dashboard:
a ``(host_ref, provider)`` pair whose *first-ever* proxy provider-API call falls
inside a lookback window — the shadow-AI-in-built-software signal.

Until this module, that signal was view-only. SOC never got paged. This
evaluator runs after each evaluate-db event pass (same lifecycle as the
team-budget evaluator), inserts an observe-only finding per new pair, and
relies on the existing notifier path (webhook / Sentinel / Google Chat)
so a configured SOC channel receives a real alert.

Edge-trigger: finding ``UNIQUE (rule_id, event_id)`` uses the first event's
id, so re-runs never re-page. Lookback bounds deploy-time noise so an install
that already has months of history does not dump a backlog onto the SOC the
day this code lands.

Metadata-only: host_ref is a pseudonym; no IP, path, or content crosses the
alert boundary.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .engine import DECISION, FINDING_SCHEMA

# Stable namespace so synthetic ids (if we ever need them) and rule identity are
# deterministic across runs. Primary edge-trigger still uses the real first
# event_id when available.
NEW_SOURCE_NS = uuid.UUID("a5750000-0000-4000-8000-000000000575")

RULE_ID = "app-llm-new-source"
RULE_SEVERITY = "medium"
RULE_TITLE = "New source calling a provider API (first ever)"

# Mirrors apps/api PROVIDER_API_PROVIDERS / collectors proxy provider-api rules
# for the direct LLM APIs that both employee tools and company apps hit.
DEFAULT_PROVIDERS: tuple[str, ...] = (
    # Mirrors collectors/proxy/endpoints.json category=provider-api and
    # apps/api PROVIDER_API_PROVIDERS. CI:
    # scripts/check_provider_catalogue_drift.py.
    "anthropic",
    "openai",
    "azure_openai",
    "aws_bedrock",
    "google",
    "mistral",
    "cohere",
    "groq",
    "xai",
    "openrouter",
    "moonshot",
    "together",
    "fireworks",
)

# Default lookback: long enough to cover a quiet weekend + a delayed poller,
# short enough that a first deploy does not replay months of first-seen history.
DEFAULT_LOOKBACK_HOURS = 48
MAX_FINDINGS_PER_RUN = 100

NEW_SOURCES_QUERY = """
SELECT host_ref, provider, first_seen, traffic_class, first_event_id FROM (
  SELECT
    e.host_ref,
    e.provider,
    MIN(e.ts) AS first_seen,
    (array_agg(COALESCE(e.traffic_class, 'unknown') ORDER BY e.ts ASC, e.event_id ASC))[1]
      AS traffic_class,
    (array_agg(e.event_id ORDER BY e.ts ASC, e.event_id ASC))[1] AS first_event_id
  FROM events e
  WHERE e.source = 'proxy'
    AND e.provider = ANY(%s)
  GROUP BY 1, 2
) f
WHERE f.first_seen >= now() - (%s || ' hours')::interval
ORDER BY first_seen DESC
LIMIT %s
"""


@dataclass
class NewSourceRunSummary:
    candidates: int = 0
    findings: int = 0
    findings_inserted: int = 0
    skipped_missing_table: bool = False
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS
    providers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def lookback_hours_from_env(env: dict | None = None) -> int:
    """``APP_LLM_NEW_SOURCE_LOOKBACK_HOURS`` — positive int, default 48."""
    env = env if env is not None else os.environ
    raw = env.get("APP_LLM_NEW_SOURCE_LOOKBACK_HOURS")
    if raw is None or str(raw).strip() == "":
        return DEFAULT_LOOKBACK_HOURS
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"APP_LLM_NEW_SOURCE_LOOKBACK_HOURS must be a positive integer, got {raw!r}"
        ) from exc
    if value <= 0:
        raise ValueError(
            f"APP_LLM_NEW_SOURCE_LOOKBACK_HOURS must be > 0, got {value}"
        )
    return value


def providers_from_env(env: dict | None = None) -> tuple[str, ...]:
    """``APP_LLM_NEW_SOURCE_PROVIDERS`` comma list, or the default provider-api set."""
    env = env if env is not None else os.environ
    raw = env.get("APP_LLM_NEW_SOURCE_PROVIDERS")
    if raw is None or str(raw).strip() == "":
        return DEFAULT_PROVIDERS
    parts = tuple(p.strip() for p in str(raw).split(",") if p.strip())
    return parts or DEFAULT_PROVIDERS


def _build_finding(
    *,
    host_ref: str,
    provider: str,
    first_seen: datetime | str,
    traffic_class: str,
    first_event_id: str | None,
    policy_hash: str,
    ruleset_version: int | str,
    now: datetime,
) -> dict:
    if isinstance(first_seen, datetime):
        first_seen_iso = first_seen.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        ts_iso = first_seen_iso
    else:
        first_seen_iso = str(first_seen)
        ts_iso = first_seen_iso

    # Prefer the real first event so SOC can pivot; fall back to a stable
    # synthetic id if the row somehow lacks an event_id (should not happen).
    if first_event_id:
        event_id = str(first_event_id)
    else:
        event_id = str(
            uuid.uuid5(NEW_SOURCE_NS, f"{host_ref}:{provider}:{first_seen_iso}")
        )

    host_short = (host_ref or "")[:12]
    title = f"New source calling {provider} API (host {host_short}…)" if host_short else RULE_TITLE

    evidence = {
        "event_ids": [event_id],
        "detail": {
            "signal": "app_llm_new_source",
            "host_ref": host_ref,
            "provider": provider,
            "first_seen": first_seen_iso,
            "traffic_class": traffic_class,
        },
        "group_by": {"host_ref": host_ref, "provider": provider},
        "matched": [
            {
                "detector": "app-llm:new-source",
                "category": "policy",
                "severity": RULE_SEVERITY,
            }
        ],
        "context": {
            "tool": "proxy",
            "provider": provider,
            "host_ref": host_ref,
            "traffic_class": traffic_class,
            "source": "app_llm_new_source_evaluator",
        },
    }
    return {
        "schema": FINDING_SCHEMA,
        "finding_id": str(uuid.uuid4()),
        "rule_id": RULE_ID,
        "ruleset_version": ruleset_version,
        "policy_hash": policy_hash,
        "severity": RULE_SEVERITY,
        "title": title,
        "decision": DECISION,
        "ts": ts_iso if ts_iso.endswith("Z") or "+" in ts_iso[10:] else now.isoformat(),
        "subject": {"user_ref": None, "host_ref": host_ref},
        "evidence": evidence,
    }


def _fetch_candidates(
    conn: Any,
    *,
    providers: tuple[str, ...],
    lookback_hours: int,
    limit: int = MAX_FINDINGS_PER_RUN,
) -> list[dict] | None:
    """Return new-source rows, or None when the events table is missing."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                NEW_SOURCES_QUERY,
                (list(providers), str(lookback_hours), limit),
            )
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).lower()
        if "events" in msg and (
            "does not exist" in msg
            or "undefinedtable" in msg
            or "undefined column" in msg
            or "undefinedcolumn" in msg
        ):
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                pass
            return None
        raise

    out: list[dict] = []
    for row in rows:
        host_ref, provider, first_seen, traffic_class, first_event_id = row
        out.append({
            "host_ref": host_ref,
            "provider": provider,
            "first_seen": first_seen,
            "traffic_class": traffic_class or "unknown",
            "first_event_id": str(first_event_id) if first_event_id is not None else None,
        })
    return out


def evaluate_new_sources(
    conn: Any,
    *,
    policy_hash: str = "new-source-evaluator",
    ruleset_version: int | str = 1,
    now: datetime | None = None,
    lookback_hours: int | None = None,
    providers: tuple[str, ...] | None = None,
    env: dict | None = None,
) -> tuple[list[dict], NewSourceRunSummary]:
    """Find first-ever proxy provider-API callers inside the lookback window."""
    summary = NewSourceRunSummary()
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    try:
        lookback = lookback_hours if lookback_hours is not None else lookback_hours_from_env(env)
        provs = providers if providers is not None else providers_from_env(env)
    except ValueError as exc:
        summary.errors.append(str(exc))
        return [], summary

    summary.lookback_hours = lookback
    summary.providers = list(provs)

    try:
        candidates = _fetch_candidates(conn, providers=provs, lookback_hours=lookback)
    except Exception as exc:  # noqa: BLE001
        summary.errors.append(f"fetch new sources failed: {exc}")
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        return [], summary

    if candidates is None:
        summary.skipped_missing_table = True
        return [], summary

    summary.candidates = len(candidates)
    findings: list[dict] = []
    for c in candidates:
        findings.append(
            _build_finding(
                host_ref=c["host_ref"],
                provider=c["provider"],
                first_seen=c["first_seen"],
                traffic_class=c["traffic_class"],
                first_event_id=c["first_event_id"],
                policy_hash=policy_hash,
                ruleset_version=ruleset_version,
                now=now,
            )
        )
        summary.findings += 1
    return findings, summary


def apply_new_source_findings(
    conn: Any,
    findings: list[dict],
    insert_finding_fn,
) -> list[dict]:
    """Insert findings; ON CONFLICT makes re-runs silent. Returns inserted rows."""
    inserted: list[dict] = []
    for finding in findings:
        if insert_finding_fn(conn, finding):
            inserted.append(finding)
    return inserted
