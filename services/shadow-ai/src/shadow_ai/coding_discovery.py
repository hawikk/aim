"""Emit ``unknown_ai_coding_tool`` findings for uncatalogued coding signals (AIM-644).

Discovery only (decision=observe). Catalogued tools never emit here — they are
already named. Known-non-AI apps are suppressed. Analyst disposition lives on
the platform ``findings`` table (status: new → acknowledged|resolved|false_positive).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .catalogue import Catalogue, slugify
from .coding_heuristics import looks_like_ai_coding_tool
from .db import CodingDiscoveryFinding, OAuthGrant, aware
from .process_source import ProcessSource
from .proxy_source import ProxySource

RULE_ID = "unknown_ai_coding_tool"
FINDING_SCHEMA = "guardrail.finding/v1"
POLICY_HASH = "aim-644-coding-discovery-v1"
DECISION = "observe"
SEVERITY_STRONG = "medium"
SEVERITY_WEAK = "low"


def _stable_uuid(*parts: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, "aim:" + ":".join(parts))


def build_coding_discoveries(
    session: Session,
    catalogue: Catalogue,
    proxy_source: ProxySource,
    process_source: ProcessSource,
) -> list[CodingDiscoveryFinding]:
    now = datetime.now(timezone.utc)
    # key = (signal_source, signal_value) → finding builder state
    buckets: dict[tuple[str, str], dict] = {}

    # --- IdP OAuth: uncatalogued grants that look like coding tools ---
    grants = session.execute(select(OAuthGrant)).scalars().all()
    for g in grants:
        if g.last_action != "authorize":
            continue
        tool = catalogue.match_oauth_app(g.app_name, g.client_id)
        if tool is not None:
            continue  # already named in catalogue
        if catalogue.is_known_non_ai(g.app_name):
            continue
        hit = looks_like_ai_coding_tool(name=g.app_name)
        if not hit.matched:
            continue
        key = ("idp_oauth", slugify(g.app_name))
        b = buckets.setdefault(
            key,
            {
                "signal_source": "idp_oauth",
                "signal_value": g.app_name,
                "tool_slug": slugify(g.app_name),
                "patterns": set(),
                "strength": hit.strength,
                "identities": set(),
                "host_count": 0,
                "event_count": 0,
                "first_seen": None,
                "last_seen": None,
            },
        )
        b["patterns"].update(hit.patterns)
        b["identities"].add(g.user_pseudonym)
        b["first_seen"] = _min_dt(b["first_seen"], g.first_seen)
        b["last_seen"] = _max_dt(b["last_seen"], g.last_seen)
        if hit.strength == "strong":
            b["strength"] = "strong"

    # --- Proxy domains / tool_raw ---
    for obs in proxy_source.fetch():
        tool = catalogue.match_oauth_app(obs.tool_raw, None) or catalogue.match_domain(
            obs.tool_raw
        )
        if tool is not None:
            continue
        if catalogue.is_known_non_ai(obs.tool_raw):
            continue
        hit = looks_like_ai_coding_tool(name=obs.tool_raw, domain=obs.tool_raw)
        if not hit.matched:
            continue
        key = ("proxy_domain", slugify(obs.tool_raw))
        b = buckets.setdefault(
            key,
            {
                "signal_source": "proxy_domain",
                "signal_value": obs.tool_raw,
                "tool_slug": slugify(obs.tool_raw),
                "patterns": set(),
                "strength": hit.strength,
                "identities": set(),
                "host_count": 0,
                "event_count": 0,
                "first_seen": None,
                "last_seen": None,
            },
        )
        b["patterns"].update(hit.patterns)
        b["host_count"] = max(b["host_count"], obs.host_count)
        b["event_count"] = max(b["event_count"], obs.event_count)
        b["first_seen"] = _min_dt(b["first_seen"], obs.first_seen)
        b["last_seen"] = _max_dt(b["last_seen"], obs.last_seen)
        if hit.strength == "strong":
            b["strength"] = "strong"

    # --- Process / binary basenames ---
    for obs in process_source.fetch():
        hit = looks_like_ai_coding_tool(binary=obs.binary, name=obs.binary)
        if not hit.matched:
            continue
        # If the binary maps to a catalogue tool name/domain, skip.
        tool = catalogue.match_oauth_app(obs.binary, None) or catalogue.match_domain(
            obs.binary
        )
        if tool is not None:
            continue
        key = ("process", slugify(obs.binary))
        b = buckets.setdefault(
            key,
            {
                "signal_source": "process",
                "signal_value": obs.binary,
                "tool_slug": slugify(obs.binary),
                "patterns": set(),
                "strength": hit.strength,
                "identities": set(),
                "host_count": 0,
                "event_count": 0,
                "first_seen": None,
                "last_seen": None,
            },
        )
        b["patterns"].update(hit.patterns)
        b["host_count"] = max(b["host_count"], obs.host_count)
        b["event_count"] = max(b["event_count"], obs.event_count)
        b["first_seen"] = _min_dt(b["first_seen"], obs.first_seen)
        b["last_seen"] = _max_dt(b["last_seen"], obs.last_seen)
        if hit.strength == "strong":
            b["strength"] = "strong"

    out: list[CodingDiscoveryFinding] = []
    for b in buckets.values():
        severity = (
            SEVERITY_STRONG if b["strength"] == "strong" else SEVERITY_WEAK
        )
        finding_id = str(
            _stable_uuid(RULE_ID, b["signal_source"], b["tool_slug"])
        )
        patterns = sorted(b["patterns"])
        title = (
            f"Unknown AI coding tool: {b['signal_value']} "
            f"({b['signal_source']})"
        )
        out.append(
            CodingDiscoveryFinding(
                finding_id=finding_id,
                rule_id=RULE_ID,
                severity=severity,
                title=title,
                signal_source=b["signal_source"],
                signal_value=b["signal_value"],
                tool_slug=b["tool_slug"],
                matched_patterns=patterns,
                strength=b["strength"],
                identity_count=len(b["identities"]) or None,
                host_count=b["host_count"] or None,
                event_count=b["event_count"] or None,
                first_seen=b["first_seen"],
                last_seen=b["last_seen"],
                computed_at=now,
            )
        )
    out.sort(key=lambda r: (r.severity != "medium", r.signal_value))
    return out


def persist_coding_discoveries(
    session: Session, rows: list[CodingDiscoveryFinding]
) -> int:
    existing = {
        r.finding_id: r
        for r in session.execute(select(CodingDiscoveryFinding)).scalars().all()
    }
    seen: set[str] = set()
    for row in rows:
        seen.add(row.finding_id)
        if row.finding_id in existing:
            cur = existing[row.finding_id]
            for col in (
                "severity",
                "title",
                "signal_source",
                "signal_value",
                "tool_slug",
                "matched_patterns",
                "strength",
                "identity_count",
                "host_count",
                "event_count",
                "first_seen",
                "last_seen",
                "computed_at",
            ):
                setattr(cur, col, getattr(row, col))
        else:
            session.add(row)
    for fid, cur in existing.items():
        if fid not in seen:
            session.delete(cur)
    session.commit()
    return len(rows)


def upsert_platform_coding_findings(
    session: Session, rows: list[CodingDiscoveryFinding]
) -> int:
    """Best-effort upsert into platform findings (analyst disposition path)."""
    try:
        session.execute(text("SELECT 1 FROM findings LIMIT 1"))
    except Exception:
        session.rollback()
        return 0

    written = 0
    for row in rows:
        event_id = str(_stable_uuid("event", row.finding_id))
        # Unattributed discoveries use host_ref-only subject when no identity.
        subject = {
            "user_ref": None,
            "host_ref": None,
            "tool_slug": row.tool_slug,
        }
        evidence = {
            "source_uri": f"aim:/shadow-ai/coding-discovery/{row.finding_id}",
            "detail_count": 1,
            "summary": row.title,
            "finding_type": RULE_ID,
            "signal_source": row.signal_source,
            "signal_value": row.signal_value,
            "tool_slug": row.tool_slug,
            "matched_patterns": row.matched_patterns,
            "strength": row.strength,
            "identity_count": row.identity_count,
            "host_count": row.host_count,
            "event_count": row.event_count,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "disposition_hint": (
                "Analyst path: acknowledge → catalogue PR (promote to fixed "
                "catalogue) or mark false_positive if not an AI coding tool. "
                "Observe only — never blocks."
            ),
        }
        session.execute(
            text(
                """
                INSERT INTO findings (
                  finding_id, ts, detected_at, rule_id, severity, title,
                  subject, evidence, policy_hash, decision, event_id, status
                ) VALUES (
                  CAST(:finding_id AS uuid), :ts, now(), :rule_id, :severity, :title,
                  CAST(:subject AS jsonb), CAST(:evidence AS jsonb),
                  :policy_hash, :decision, CAST(:event_id AS uuid), 'new'
                )
                ON CONFLICT (rule_id, event_id) DO UPDATE SET
                  ts = EXCLUDED.ts,
                  severity = EXCLUDED.severity,
                  title = EXCLUDED.title,
                  subject = EXCLUDED.subject,
                  evidence = EXCLUDED.evidence,
                  policy_hash = EXCLUDED.policy_hash
                """
            ),
            {
                "finding_id": row.finding_id,
                "ts": row.last_seen
                or row.first_seen
                or datetime.now(timezone.utc),
                "rule_id": RULE_ID,
                "severity": row.severity,
                "title": row.title,
                "subject": json.dumps(subject),
                "evidence": json.dumps(evidence),
                "policy_hash": POLICY_HASH,
                "decision": DECISION,
                "event_id": event_id,
            },
        )
        written += 1
    session.commit()
    return written


def _min_dt(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return min(aware(a), aware(b))


def _max_dt(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return max(aware(a), aware(b))
