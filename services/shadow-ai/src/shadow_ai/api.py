"""FastAPI surface: health, sync trigger, discovery inventory, closed-loop ops.

The dashboard (apps/api) reads shadow tables from Postgres directly; these
endpoints are for operations (triggering syncs) and for local/dev inspection.
AIM-626 adds discovery-queue + disposition endpoints on this service too.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from .catalogue import Catalogue
from .coding_discovery import (
    build_coding_discoveries,
    persist_coding_discoveries,
    upsert_platform_coding_findings,
)
from .config import Settings
from .db import Base, DiscoveryQueueRow, Disposition, GrantFinding, OAuthGrant, ToolInventoryRow
from .discovery import (
    discovery_lag_metrics,
    queue_row_to_dict,
    transition_status,
    upsert_discovery_queue,
)
from .disposition import (
    disposition_to_dict,
    propose_enforce_candidates,
    record_disposition,
)
from .findings import (
    build_grant_findings,
    persist_grant_findings,
    upsert_platform_findings,
)
from .grant_source import build_source
from .inventory import build_inventory, persist_inventory
from .process_source import build_process_source
from .proxy_source import build_proxy_source
from .sync import purge_expired_revokes, sync_grants


class DispositionBody(BaseModel):
    target_kind: str
    target_key: str
    action: str
    reason: str = Field(min_length=3)
    actor: str = Field(min_length=1)
    finding_id: str | None = None
    app_name: str | None = None
    tool_id: str | None = None
    client_id: str | None = None
    metadata: dict | None = None


class QueueStatusBody(BaseModel):
    status: str


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    engine = create_engine(settings.database_url)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    catalogue = Catalogue.load(settings.catalogue_path)

    app = FastAPI(title="shadow-ai", version="0.3.0")

    def get_session():
        with sessions() as s:
            yield s

    def run_sync(session: Session) -> dict:
        grant_stats = sync_grants(session, build_source(settings), settings.pseudonym_secret)
        purged = purge_expired_revokes(session, settings.revoked_retention_days)
        rows = build_inventory(session, catalogue, build_proxy_source(settings))
        persist_inventory(session, rows)
        findings = build_grant_findings(session, catalogue)
        n_findings = persist_grant_findings(session, findings)
        coding = build_coding_discoveries(
            session,
            catalogue,
            build_proxy_source(settings),
            build_process_source(settings),
        )
        n_coding = persist_coding_discoveries(session, coding)
        n_platform = 0
        n_platform_coding = 0
        if settings.emit_platform_findings:
            n_platform = upsert_platform_findings(session, findings)
            n_platform_coding = upsert_platform_coding_findings(session, coding)
        discovery_stats = upsert_discovery_queue(session, catalogue)
        lag = discovery_lag_metrics(session)
        return {
            **grant_stats,
            "revoked_grants_purged": purged,
            "inventory_tools": len(rows),
            "unapproved_ai_saas_grant_findings": n_findings,
            "unknown_ai_coding_tool_findings": n_coding,
            "platform_findings_upserted": n_platform,
            "platform_coding_findings_upserted": n_platform_coding,
            **discovery_stats,
            **lag,
        }

    @app.get("/health")
    def health():
        return {
            "ok": True,
            "grant_source": settings.grant_source,
            "grant_sources": settings.grant_sources or None,
            "proxy_source": settings.proxy_source,
        }

    @app.post("/sync")
    def sync(session: Session = Depends(get_session)):
        return run_sync(session)

    @app.get("/v1/shadow-ai/inventory")
    def inventory(session: Session = Depends(get_session)):
        rows = session.execute(
            select(ToolInventoryRow).order_by(ToolInventoryRow.risk_score.desc())
        ).scalars().all()
        return {"tools": [_row_to_dict(r) for r in rows]}

    @app.get("/v1/shadow-ai/grants")
    def grants(session: Session = Depends(get_session)):
        """Analyst list: AI SaaS apps authorized via corporate IdP (pseudonyms)."""
        grants_rows = session.execute(
            select(OAuthGrant).order_by(OAuthGrant.last_seen.desc())
        ).scalars().all()
        findings = {
            (f.user_pseudonym, f.app_name, f.idp_source): f
            for f in session.execute(select(GrantFinding)).scalars().all()
        }
        out = []
        for g in grants_rows:
            if g.last_action != "authorize":
                continue
            tool = catalogue.match_oauth_app(g.app_name, g.client_id)
            if tool is None and catalogue.is_known_non_ai(g.app_name):
                continue
            finding = findings.get((g.user_pseudonym, g.app_name, g.idp_source))
            out.append(
                {
                    "user_ref": g.user_pseudonym,
                    "app_name": g.app_name,
                    "tool_id": tool.id if tool else None,
                    "client_id": g.client_id,
                    "idp_source": g.idp_source,
                    "scopes": g.scopes,
                    "first_seen": g.first_seen.isoformat() if g.first_seen else None,
                    "last_seen": g.last_seen.isoformat() if g.last_seen else None,
                    "sanctioned": tool.sanctioned if tool else None,
                    "catalogued": tool is not None,
                    "finding_type": finding.rule_id if finding else None,
                    "finding_id": finding.finding_id if finding else None,
                    "severity": finding.severity if finding else None,
                }
            )
        return {"grants": out}

    @app.get("/v1/shadow-ai/discovery-queue")
    def discovery_queue(
        status: str | None = None,
        session: Session = Depends(get_session),
    ):
        q = select(DiscoveryQueueRow).order_by(DiscoveryQueueRow.last_seen.desc())
        rows = session.execute(q).scalars().all()
        if status:
            rows = [r for r in rows if r.status == status]
        return {"items": [queue_row_to_dict(r) for r in rows]}

    @app.post("/v1/shadow-ai/discovery-queue/{queue_id}/status")
    def discovery_queue_status(
        queue_id: str,
        body: QueueStatusBody,
        session: Session = Depends(get_session),
    ):
        try:
            row = transition_status(session, queue_id, body.status)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        if row is None:
            raise HTTPException(status_code=404, detail="queue item not found")
        return queue_row_to_dict(row)

    @app.get("/v1/shadow-ai/dispositions")
    def list_dispositions(session: Session = Depends(get_session)):
        rows = session.execute(
            select(Disposition).order_by(Disposition.created_at.desc()).limit(500)
        ).scalars().all()
        return {"dispositions": [disposition_to_dict(r) for r in rows]}

    @app.post("/v1/shadow-ai/dispositions")
    def create_disposition(
        body: DispositionBody,
        session: Session = Depends(get_session),
    ):
        try:
            row = record_disposition(
                session,
                target_kind=body.target_kind,
                target_key=body.target_key,
                action=body.action,
                reason=body.reason,
                actor=body.actor,
                finding_id=body.finding_id,
                app_name=body.app_name,
                tool_id=body.tool_id,
                client_id=body.client_id,
                metadata=body.metadata,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return disposition_to_dict(row)

    @app.get("/v1/shadow-ai/enforce-candidates")
    def enforce_candidates(session: Session = Depends(get_session)):
        return {"candidates": propose_enforce_candidates(session)}

    @app.get("/v1/shadow-ai/idp-summary")
    def idp_summary(session: Session = Depends(get_session)):
        """Multi-IdP grant inventory counts (AIM-626 / AIM-777)."""
        rows = session.execute(
            select(
                OAuthGrant.idp_source,
                func.count().label("n"),
            )
            .where(OAuthGrant.last_action == "authorize")
            .group_by(OAuthGrant.idp_source)
        ).all()
        by_idp = {r[0]: int(r[1]) for r in rows}
        return {
            "active_grants": sum(by_idp.values()),
            "by_idp_source": by_idp,
            "idp_count": len(by_idp),
        }

    return app


def _row_to_dict(r: ToolInventoryRow) -> dict:
    return {
        "tool_id": r.tool_id,
        "name": r.name,
        "vendor": r.vendor,
        "catalogued": r.catalogued,
        "sanctioned": r.sanctioned,
        "data_access_class": r.data_access_class,
        "sources": r.sources,
        "attribution": r.attribution,
        "identity_count": r.identity_count,
        "scopes": r.scopes,
        "scope_classes": r.scope_classes,
        "first_seen": r.first_seen.isoformat() if r.first_seen else None,
        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        "risk": {
            "score": r.risk_score,
            "band": r.risk_band,
            "components": r.risk_components,
        },
        "computed_at": r.computed_at.isoformat() if r.computed_at else None,
    }
