"""Continuous catalogue ops: discovery queue for uncatalogued IdP grants (AIM-776).

On every ``shadow-ai sync``:
- active (authorize) grants that do not match a catalogue tool and are not
  known-non-AI upsert into ``shadow_ai_discovery_queue``;
- each candidate gets a draft catalogue JSON fragment (``proposed_entry``)
  ready for PR review — adding a tool remains a data change, never code.

Status transitions (analyst-driven via API): open → proposed | catalogued |
dismissed | known_non_ai. Sync auto-closes open/proposed rows when the
catalogue catches up.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .catalogue import Catalogue, slugify
from .db import (
    DISCOVERY_OPEN_STATUSES,
    DISCOVERY_STATUSES,
    DISCOVERY_TRANSITIONS,
    DiscoveryQueueRow,
    OAuthGrant,
    aware,
    utcnow,
)


def _stable_queue_id(app_name: str, client_id: str) -> str:
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"aim:shadow-ai-discovery:{app_name}:{client_id or ''}",
        )
    )


def _norm_client_id(client_id: str | None) -> str:
    return (client_id or "").strip()


def _normalize_client_ids(
    client_id: str | list[str] | None = None,
    client_ids: list[str] | None = None,
) -> list[str]:
    """Accept a single client_id, a list, or an explicit client_ids kwarg."""
    out: list[str] = []
    if client_ids:
        out.extend(c for c in client_ids if c)
    if isinstance(client_id, list):
        out.extend(c for c in client_id if c)
    elif client_id:
        out.append(client_id)
    # stable unique preserve order
    seen: set[str] = set()
    uniq: list[str] = []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def draft_catalogue_entry(
    app_name: str,
    client_id: str | list[str] | None = None,
    idp_sources: list[str] | None = None,
    scopes: list[str] | None = None,
    *,
    client_ids: list[str] | None = None,
) -> dict:
    """Draft catalogue JSON fragment for PR review (AIM-776).

    Shape mirrors ``catalogue/ai-tools.json`` tool entries. Fields that need a
    human (vendor, domains, sanctioned) stay conservative defaults.

    ``client_id`` may be a single id string or a list of ids (tests + call
    sites use both). Prefer ``client_ids=`` when calling with a list.
    """
    name = (app_name or "").strip() or "Unknown App"
    tool_id = slugify(name)
    pattern = name.lower()
    clients = _normalize_client_ids(client_id, client_ids)
    idps = sorted({s for s in (idp_sources or []) if s})
    scope_sample = ", ".join(sorted(set(scopes or []))[:8])
    notes = (
        f"AUTO-DRAFT from shadow-ai discovery queue (AIM-776). "
        f"IdP sources: {', '.join(idps) if idps else 'unknown'}. "
        f"Requires PR review before merge into catalogue."
    )
    if scope_sample:
        notes += f" Observed scopes (sample): {scope_sample}."
    return {
        "id": tool_id,
        "name": name,
        "vendor": "",
        "sanctioned": False,
        "data_access_class": "unknown",
        "domains": [],
        "oauth": {
            "client_ids": clients,
            "app_name_patterns": [pattern] if pattern else [],
        },
        "notes": notes,
    }


def draft_proposed_entry(
    app_name: str,
    client_ids: str | list[str] | None = None,
    *,
    scopes: list[str] | None = None,
    idp_sources: list[str] | None = None,
    client_id: str | None = None,
) -> dict:
    """Draft entry using the list-oriented client_ids arg (AIM-776 tests)."""
    return draft_catalogue_entry(
        app_name,
        client_id=client_id if client_id is not None else client_ids,
        idp_sources=idp_sources,
        scopes=scopes,
    )


def _aggregate_uncatalogued(
    session: Session, catalogue: Catalogue
) -> dict[tuple[str, str], dict]:
    """Group active grants by (app_name, client_id) for uncatalogued apps."""
    buckets: dict[tuple[str, str], dict] = {}
    grants = session.execute(select(OAuthGrant)).scalars().all()
    for g in grants:
        if g.last_action != "authorize":
            continue
        tool = catalogue.match_oauth_app(g.app_name, g.client_id)
        if tool is not None:
            continue
        if catalogue.is_known_non_ai(g.app_name):
            continue
        cid = _norm_client_id(g.client_id)
        key = (g.app_name, cid)
        b = buckets.get(key)
        if b is None:
            b = {
                "app_name": g.app_name,
                "client_id": cid,
                "idp_sources": set(),
                "identities": set(),
                "grant_count": 0,
                "scopes": set(),
                "first_seen": None,
                "last_seen": None,
            }
            buckets[key] = b
        b["idp_sources"].add(g.idp_source)
        b["identities"].add(g.user_pseudonym)
        b["grant_count"] += 1
        b["scopes"].update(g.scopes or [])
        fs = aware(g.first_seen) if g.first_seen else None
        ls = aware(g.last_seen) if g.last_seen else None
        if fs is not None:
            b["first_seen"] = fs if b["first_seen"] is None else min(b["first_seen"], fs)
        if ls is not None:
            b["last_seen"] = ls if b["last_seen"] is None else max(b["last_seen"], ls)
    return buckets


def refresh_discovery_queue(session: Session, catalogue: Catalogue) -> dict:
    """Upsert uncatalogued active grants into the discovery queue.

    Returns stats consumed by CLI/API sync and summary lag metrics.
    """
    now = datetime.now(timezone.utc)
    buckets = _aggregate_uncatalogued(session, catalogue)
    existing = {
        r.queue_id: r
        for r in session.execute(select(DiscoveryQueueRow)).scalars().all()
    }
    seen: set[str] = set()
    upserted = 0
    auto_catalogued = 0
    auto_known_non_ai = 0

    for (app_name, client_id), b in buckets.items():
        qid = _stable_queue_id(app_name, client_id)
        seen.add(qid)
        entry = draft_catalogue_entry(
            app_name,
            client_id or None,
            idp_sources=sorted(b["idp_sources"]),
            scopes=sorted(b["scopes"]),
        )
        first_seen = b["first_seen"] or now
        last_seen = b["last_seen"] or now
        idp_sources = sorted(b["idp_sources"])
        identity_count = len(b["identities"])
        grant_count = b["grant_count"]
        proposed_tool_id = entry["id"]

        if qid in existing:
            row = existing[qid]
            row.app_name = app_name
            row.client_id = client_id
            row.idp_sources = idp_sources
            row.identity_count = identity_count
            row.grant_count = grant_count
            row.first_seen = min(aware(row.first_seen), first_seen)
            row.last_seen = max(aware(row.last_seen), last_seen)
            row.proposed_tool_id = proposed_tool_id
            # Refresh draft while still open-ish so PR fragments track newly
            # observed client ids / scopes. Terminal statuses keep last draft.
            if row.status in DISCOVERY_OPEN_STATUSES:
                row.proposed_entry = entry
            row.updated_at = now
            upserted += 1
        else:
            session.add(
                DiscoveryQueueRow(
                    queue_id=qid,
                    app_name=app_name,
                    client_id=client_id,
                    idp_sources=idp_sources,
                    identity_count=identity_count,
                    grant_count=grant_count,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    proposed_tool_id=proposed_tool_id,
                    proposed_entry=entry,
                    status="open",
                    updated_at=now,
                )
            )
            upserted += 1

    # Auto-close open/proposed rows that catalogue (or known-non-AI) now covers.
    for qid, row in existing.items():
        if qid in seen:
            continue
        if row.status not in DISCOVERY_OPEN_STATUSES:
            continue
        tool = catalogue.match_oauth_app(row.app_name, row.client_id or None)
        if tool is not None:
            row.status = "catalogued"
            row.updated_at = now
            auto_catalogued += 1
            continue
        if catalogue.is_known_non_ai(row.app_name):
            row.status = "known_non_ai"
            row.updated_at = now
            auto_known_non_ai += 1

    session.commit()
    lag = discovery_lag_metrics(session)
    return {
        "discovery_queue_upserted": upserted,
        "discovery_queue_auto_catalogued": auto_catalogued,
        "discovery_queue_auto_known_non_ai": auto_known_non_ai,
        **lag,
    }


# Alias for call sites that prefer upsert naming.
upsert_discovery_queue = refresh_discovery_queue


def set_queue_status(
    session: Session, queue_id: str, new_status: str
) -> DiscoveryQueueRow | None:
    """Apply a status transition. Returns the row, or None if missing.

    Raises ValueError on illegal status / transition.
    """
    if new_status not in DISCOVERY_STATUSES:
        raise ValueError(
            f"invalid status {new_status!r}; expected one of "
            f"{sorted(DISCOVERY_STATUSES)}"
        )
    row = session.get(DiscoveryQueueRow, queue_id)
    if row is None:
        return None
    if new_status == row.status:
        return row
    allowed = DISCOVERY_TRANSITIONS.get(row.status, frozenset())
    if new_status not in allowed:
        raise ValueError(
            f"cannot transition {row.status!r} → {new_status!r}; "
            f"allowed: {sorted(allowed)}"
        )
    row.status = new_status
    row.updated_at = utcnow()
    session.commit()
    return row


transition_status = set_queue_status


def discovery_lag_metrics(session: Session) -> dict:
    """Open-count + oldest open candidate age (seconds) for summary strip."""
    now = datetime.now(timezone.utc)
    open_rows = (
        session.execute(
            select(DiscoveryQueueRow).where(DiscoveryQueueRow.status == "open")
        )
        .scalars()
        .all()
    )
    open_count = len(open_rows)
    if not open_rows:
        return {
            "discovery_queue_open": 0,
            "discovery_queue_oldest_open_age_seconds": None,
            "discovery_queue_oldest_open_first_seen": None,
        }
    oldest = min(aware(r.first_seen) for r in open_rows)
    age = max(0, int((now - oldest).total_seconds()))
    return {
        "discovery_queue_open": open_count,
        "discovery_queue_oldest_open_age_seconds": age,
        "discovery_queue_oldest_open_first_seen": oldest.isoformat(),
    }


def queue_to_dict(row: DiscoveryQueueRow) -> dict:
    return {
        "queue_id": row.queue_id,
        "app_name": row.app_name,
        "client_id": row.client_id or None,
        "idp_sources": list(row.idp_sources or []),
        "identity_count": row.identity_count,
        "grant_count": row.grant_count,
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        "proposed_tool_id": row.proposed_tool_id,
        "proposed_entry": row.proposed_entry,
        "status": row.status,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


queue_row_to_dict = queue_to_dict
