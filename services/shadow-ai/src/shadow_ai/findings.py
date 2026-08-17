"""Emit first-class shadow findings for AI SaaS OAuth grants.

Finding type: ``unapproved_ai_saas_grant``

Emitted for every *active* grant (last_action=authorize) whose matched
catalogue tool is unsanctioned OR uncatalogued. Sanctioned tools (Claude
Code / Cursor / Kilo Code) do not emit this finding.

Subject carries ``user_ref`` = user_pseudonym only — never email. Evidence
carries app name, client_id, scopes, first/last seen, idp_source. No prompt
content.

Idempotency: deterministic UUID5 for (rule_id, subject, app, idp) so re-sync
upserts rather than duplicates. Writes into the platform ``findings`` table
when present (Postgres dogfood); always materializes into
``shadow_ai_findings`` for the analyst grant list.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .catalogue import Catalogue
from .db import GrantFinding, OAuthGrant, aware
from .disposition import active_suppressions

RULE_ID = "unapproved_ai_saas_grant"
FINDING_SCHEMA = "guardrail.finding/v1"
POLICY_HASH = "aim-504-saas-oauth-v1"
DECISION = "observe"
SEVERITY_UNSANCTIONED = "high"
SEVERITY_UNCATALOGUED = "medium"


def _stable_uuid(*parts: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, "aim:" + ":".join(parts))


def _should_emit(tool) -> tuple[bool, str]:
    """Return (emit?, severity). Sanctioned catalogue tools never emit."""
    if tool is None:
        return True, SEVERITY_UNCATALOGUED
    if tool.sanctioned is True:
        return False, ""
    if tool.sanctioned is False:
        return True, SEVERITY_UNSANCTIONED
    return True, SEVERITY_UNCATALOGUED


def build_grant_findings(session: Session, catalogue: Catalogue) -> list[GrantFinding]:
    """Build unapproved grant findings, honoring allow / known_non_ai.

    Analyst dispositions with action ``allow`` or ``known_non_ai`` suppress
    re-emit for matching finding_id / app_name / tool_id. ``persist_grant_findings``
    then drops any previously stored finding that no longer appears here.
    """
    now = datetime.now(timezone.utc)
    out: list[GrantFinding] = []
    suppress = active_suppressions(session)
    grants = session.execute(select(OAuthGrant)).scalars().all()
    for g in grants:
        if g.last_action != "authorize":
            continue
        tool = catalogue.match_oauth_app(g.app_name, g.client_id)
        if tool is None and catalogue.is_known_non_ai(g.app_name):
            continue
        # closed loop: allow / known_non_ai dispositions suppress re-emit
        app_key = (g.app_name or "").strip().lower()
        if app_key and app_key in suppress["apps"]:
            continue
        if tool is not None and tool.id in suppress["tools"]:
            continue
        emit, severity = _should_emit(tool)
        if not emit:
            continue
        finding_id = str(
            _stable_uuid(RULE_ID, g.idp_source, g.app_name, g.user_pseudonym)
        )
        if finding_id in suppress["findings"]:
            continue
        if tool is None:
            title = f"Uncatalogued AI SaaS grant: {g.app_name}"
        elif tool.sanctioned is False:
            title = f"Unapproved AI SaaS grant: {tool.name}"
        else:
            title = f"AI SaaS grant: {tool.name}"

        out.append(
            GrantFinding(
                finding_id=finding_id,
                rule_id=RULE_ID,
                severity=severity,
                title=title,
                user_pseudonym=g.user_pseudonym,
                app_name=g.app_name,
                tool_id=tool.id if tool else None,
                client_id=g.client_id,
                idp_source=g.idp_source,
                scopes=list(g.scopes or []),
                first_seen=aware(g.first_seen),
                last_seen=aware(g.last_seen),
                sanctioned=tool.sanctioned if tool else None,
                catalogued=tool is not None,
                computed_at=now,
            )
        )
    return out


def persist_grant_findings(session: Session, rows: list[GrantFinding]) -> int:
    existing = {
        r.finding_id: r
        for r in session.execute(select(GrantFinding)).scalars().all()
    }
    seen: set[str] = set()
    for row in rows:
        seen.add(row.finding_id)
        if row.finding_id in existing:
            cur = existing[row.finding_id]
            for col in (
                "severity",
                "title",
                "user_pseudonym",
                "app_name",
                "tool_id",
                "client_id",
                "idp_source",
                "scopes",
                "first_seen",
                "last_seen",
                "sanctioned",
                "catalogued",
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


def upsert_platform_findings(session: Session, rows: list[GrantFinding]) -> int:
    """Best-effort upsert into platform findings table (Postgres dogfood).

    No-op when the table is absent (unit tests on SQLite without migrations).
    """
    try:
        session.execute(text("SELECT 1 FROM findings LIMIT 1"))
    except Exception:
        session.rollback()
        return 0

    written = 0
    for row in rows:
        event_id = str(_stable_uuid("event", row.finding_id))
        subject = {"user_ref": row.user_pseudonym, "host_ref": None}
        evidence = {
            "source_uri": f"aim:/shadow-ai/grants/{row.finding_id}",
            "detail_count": 1,
            "summary": row.title,
            "app_name": row.app_name,
            "tool_id": row.tool_id,
            "client_id": row.client_id,
            "idp_source": row.idp_source,
            "scopes": row.scopes,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "finding_type": RULE_ID,
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
                "ts": row.last_seen or row.first_seen or datetime.now(timezone.utc),
                "rule_id": RULE_ID,
                "severity": row.severity,
                "title": row.title,
                "subject": __import__("json").dumps(subject),
                "evidence": __import__("json").dumps(evidence),
                "policy_hash": POLICY_HASH,
                "decision": DECISION,
                "event_id": event_id,
            },
        )
        written += 1
    session.commit()
    return written
