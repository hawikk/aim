"""Sync: pull IdP OAuth grants, pseudonymize, upsert, enforce retention.

Privacy invariants enforced HERE, at the only point cleartext identity exists:
- the email is pseudonymized immediately and never stored or logged;
- only grant-level metadata persists (app name, client id, scope URIs,
  timestamps) — no content, no URLs;
- revoked grants are purged after SHADOW_AI_REVOKED_RETENTION_DAYS.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import OAuthGrant, aware
from .grant_source import GrantSource
from .pseudonym import pseudonymize


def _parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def sync_grants(session: Session, source: GrantSource, pseudonym_secret: str) -> dict:
    seen = upserted = 0
    by_idp: dict[str, int] = {}
    for grant in source.fetch():
        seen += 1
        by_idp[grant.idp_source] = by_idp.get(grant.idp_source, 0) + 1
        pseud = pseudonymize(grant.user_email, pseudonym_secret)
        ts = _parse_ts(grant.ts) if grant.ts else datetime.now(timezone.utc)
        existing = session.execute(
            select(OAuthGrant).where(
                OAuthGrant.user_pseudonym == pseud,
                OAuthGrant.idp_source == grant.idp_source,
                OAuthGrant.app_name == grant.app_name,
            )
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                OAuthGrant(
                    user_pseudonym=pseud,
                    idp_source=grant.idp_source,
                    client_id=grant.client_id,
                    app_name=grant.app_name,
                    scopes=sorted(set(grant.scopes)),
                    first_seen=ts,
                    last_seen=ts,
                    last_action=grant.action,
                )
            )
            upserted += 1
        else:
            existing.first_seen = min(aware(existing.first_seen), ts)
            existing.last_seen = max(aware(existing.last_seen), ts)
            existing.scopes = sorted(set(existing.scopes) | set(grant.scopes))
            existing.last_action = grant.action
            if grant.client_id:
                existing.client_id = grant.client_id
            upserted += 1
    session.commit()
    return {
        "grant_events_seen": seen,
        "grants_upserted": upserted,
        "grants_by_idp_source": by_idp,
    }


def purge_expired_revokes(session: Session, retention_days: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    result = session.execute(
        delete(OAuthGrant).where(
            OAuthGrant.last_action == "revoke",
            OAuthGrant.last_seen < cutoff,
        )
    )
    session.commit()
    return result.rowcount or 0
