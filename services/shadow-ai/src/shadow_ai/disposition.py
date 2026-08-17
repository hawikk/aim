"""Analyst dispositions over shadow findings / apps (AIM-778).

Closed loop:
  allow           — suppress re-emit of matching findings on next sync
  known_non_ai    — same suppress semantics (not an AI SaaS)
  watch           — record interest; findings still emit
  propose_enforce — blocklist export candidate; findings still emit
  catalogue       — reserved for discovery-queue → catalogue PR path (AIM-776)

Active disposition = latest row per (target_kind, target_key) by created_at.
Append-only: never UPDATE/DELETE; a new INSERT supersedes the prior action.

This module is the import surface used by findings.py / api.py / tests.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Disposition, aware

TARGET_KINDS = frozenset({"finding", "app", "tool"})
ACTIONS = frozenset({"allow", "watch", "propose_enforce", "known_non_ai", "catalogue"})
SUPPRESS_ACTIONS = frozenset({"allow", "known_non_ai"})
ENFORCE_ACTIONS = frozenset({"propose_enforce"})


def _norm_key(value: str) -> str:
    return (value or "").strip()


def _norm_app(value: str) -> str:
    return (value or "").strip().lower()


def record_disposition(
    session: Session,
    *,
    target_kind: str,
    target_key: str,
    action: str,
    reason: str,
    actor: str,
    finding_id: str | None = None,
    app_name: str | None = None,
    tool_id: str | None = None,
    client_id: str | None = None,
    metadata: dict | None = None,
) -> Disposition:
    """Append a disposition row and commit."""
    if target_kind not in TARGET_KINDS:
        raise ValueError(f"target_kind must be one of {sorted(TARGET_KINDS)}")
    if action not in ACTIONS:
        raise ValueError(f"action must be one of {sorted(ACTIONS)}")
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("reason is required")
    actor = (actor or "").strip() or "unknown"
    key = _norm_app(target_key) if target_kind == "app" else _norm_key(target_key)
    if not key:
        raise ValueError("target_key is required")

    row = Disposition(
        disposition_id=str(uuid.uuid4()),
        target_kind=target_kind,
        target_key=key,
        action=action,
        reason=reason,
        actor=actor,
        finding_id=finding_id,
        app_name=app_name or (key if target_kind == "app" else None),
        tool_id=tool_id or (key if target_kind == "tool" else None),
        client_id=client_id,
        metadata_json=metadata or {},
        created_at=datetime.now(timezone.utc),
    )
    session.add(row)
    session.commit()
    return row


def active_suppressions(session: Session) -> dict[str, set[str]]:
    """Latest suppress dispositions keyed for findings builder.

    Returns ``{"apps": set, "tools": set, "findings": set}`` where app names
    are lowercased for case-insensitive match against grant app_name.
    """
    rows = session.execute(
        select(Disposition).order_by(Disposition.created_at.asc())
    ).scalars().all()
    # Walk ascending so latest wins.
    latest: dict[tuple[str, str], Disposition] = {}
    for r in rows:
        kind = r.target_kind
        key = _norm_app(r.target_key) if kind == "app" else _norm_key(r.target_key)
        if kind and key:
            latest[(kind, key)] = r

    apps: set[str] = set()
    tools: set[str] = set()
    findings: set[str] = set()
    for (kind, key), r in latest.items():
        if r.action not in SUPPRESS_ACTIONS:
            continue
        if kind == "app":
            # findings builder compares raw grant.app_name membership — keep
            # both the normalized key and the stored app_name for safety.
            apps.add(key)
            if r.app_name:
                apps.add(r.app_name)
                apps.add(_norm_app(r.app_name))
        elif kind == "tool":
            tools.add(key)
            if r.tool_id:
                tools.add(r.tool_id)
        elif kind == "finding":
            findings.add(key)
            if r.finding_id:
                findings.add(r.finding_id)
    return {"apps": apps, "tools": tools, "findings": findings}


def propose_enforce_candidates(session: Session) -> list[dict]:
    """Active propose_enforce dispositions as export candidates."""
    rows = session.execute(
        select(Disposition).order_by(Disposition.created_at.asc())
    ).scalars().all()
    latest: dict[tuple[str, str], Disposition] = {}
    for r in rows:
        kind = r.target_kind
        key = _norm_app(r.target_key) if kind == "app" else _norm_key(r.target_key)
        if kind and key:
            latest[(kind, key)] = r
    out = []
    for r in latest.values():
        if r.action not in ENFORCE_ACTIONS:
            continue
        out.append(
            {
                "disposition_id": r.disposition_id,
                "target_kind": r.target_kind,
                "target_key": r.target_key,
                "action": r.action,
                "reason": r.reason,
                "actor": r.actor,
                "app_name": r.app_name,
                "tool_id": r.tool_id,
                "client_id": r.client_id,
                "finding_id": r.finding_id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
        )
    out.sort(key=lambda c: (c.get("app_name") or c.get("target_key") or "", c.get("created_at") or ""))
    return out


def disposition_to_dict(row: Disposition) -> dict:
    return {
        "disposition_id": row.disposition_id,
        "target_kind": row.target_kind,
        "target_key": row.target_key,
        "action": row.action,
        "reason": row.reason,
        "actor": row.actor,
        "finding_id": row.finding_id,
        "app_name": row.app_name,
        "tool_id": row.tool_id,
        "client_id": row.client_id,
        "metadata": row.metadata_json or {},
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
