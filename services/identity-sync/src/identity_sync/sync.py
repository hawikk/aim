"""Directory sync: upsert users and org units from a DirectorySource into Postgres/SQLite.

Runs on a schedule (hourly in prod — Cloud Scheduler -> Cloud Run Job, or a k8s
CronJob; invoked here as `identity-sync sync`). The sync is a full upsert against
the directory snapshot; users that disappear are marked suspended rather than
deleted so historical joins keep working.

newly suspended / missing users trigger a best-effort session revoke
against the AIM API so live SSO cookies die before AIM_SESSION_TTL_HOURS.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .db import DirOrgUnit, DirUser
from .directory_source import DirectorySource
from .session_revoke import revoke_sessions


def team_from_org_unit_path(org_unit_path: str) -> str:
    """Team = top-level org unit segment. '/Engineering/Platform' -> 'Engineering'."""
    parts = [p for p in org_unit_path.split("/") if p]
    return parts[0] if parts else "Unassigned"


def sync_directory(
    session: Session,
    source: DirectorySource,
    *,
    settings: Settings | None = None,
    revoke_fn: Callable[..., dict] | None = None,
) -> dict:
    snapshot = source.fetch()
    now = datetime.now(timezone.utc)
    # Emails that transitioned to suspended this run (IdP disable or leave).
    newly_suspended_emails: list[str] = []

    for ou in snapshot.org_units:
        row = session.get(DirOrgUnit, ou.org_unit_path) or DirOrgUnit(org_unit_path=ou.org_unit_path)
        row.name = ou.name
        row.parent_path = ou.parent_path
        row.team = team_from_org_unit_path(ou.org_unit_path)
        row.last_synced_at = now
        session.merge(row)

    seen_ids: set[str] = set()
    for u in snapshot.users:
        seen_ids.add(u.id)
        existing = session.get(DirUser, u.id)
        prev_suspended = bool(existing.suspended) if existing is not None else False
        row = existing or DirUser(id=u.id)
        row.primary_email = u.primary_email
        row.full_name = u.full_name
        row.org_unit_path = u.org_unit_path
        row.team = team_from_org_unit_path(u.org_unit_path)
        row.suspended = u.suspended
        row.last_synced_at = now
        session.merge(row)
        if u.suspended and not prev_suspended and u.primary_email:
            newly_suspended_emails.append(u.primary_email)

    # Users absent from the snapshot are former employees/leavers: mark suspended,
    # keep the row so historical event joins still resolve team attribution.
    stale = session.execute(select(DirUser).where(~DirUser.id.in_(seen_ids))).scalars().all()
    for row in stale:
        if not row.suspended and row.primary_email:
            newly_suspended_emails.append(row.primary_email)
        row.suspended = True
        row.last_synced_at = now

    session.commit()

    cfg = settings or get_settings()
    revoke_result = {
        "sessions_revoked": 0,
        "sessions_revoke_failed": 0,
        "session_revoke_errors": [],
        "sessions_revoke_candidates": len(newly_suspended_emails),
    }
    if newly_suspended_emails:
        do_revoke = revoke_fn or revoke_sessions
        api_url = getattr(cfg, "aim_api_url", "") or ""
        token = getattr(cfg, "session_revoke_token", "") or ""
        # Only attempt when configured; leave candidates counted either way.
        if api_url.strip() and token.strip():
            out = do_revoke(
                newly_suspended_emails,
                api_url=api_url,
                token=token,
            )
            revoke_result["sessions_revoked"] = int(out.get("sessions_revoked", 0))
            revoke_result["sessions_revoke_failed"] = int(out.get("sessions_revoke_failed", 0))
            revoke_result["session_revoke_errors"] = list(out.get("session_revoke_errors") or [])
        else:
            # Configured-off is not a failure: operators may run sync without
            # platform revoke until the service token is provisioned.
            revoke_result["session_revoke_errors"] = []

    return {
        "org_units": len(snapshot.org_units),
        "users_synced": len(snapshot.users),
        "users_marked_suspended": len(stale),
        "users_newly_suspended": len(newly_suspended_emails),
        "synced_at": now.isoformat(),
        **revoke_result,
    }
