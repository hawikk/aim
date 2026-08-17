"""HTTP API for the identity service.

Endpoints:
- GET  /health                      liveness
- POST /sync                        trigger a directory sync (scheduler calls this)
- POST /resolve                     ingest pipeline calls this per event batch:
                                    endpoint identity in -> pseudonym + team out
- GET  /device-mappings             list device_id/os_user -> directory email
                                    bindings (AIM-455). Emails stay inside this
                                    service; events still only carry pseudonyms.
- POST /device-mappings             SECURITY-ROLE-GATED + audited. Creates the
                                    join key the resolver needs (rules 1–2).
- GET  /service-identities          list declared non-human hosts (AIM-149)
- POST /service-identities          SECURITY-ROLE-GATED + audited. Declares a host
                                    as non-human, optionally naming its operator.
- POST /join-keys/rebind-device     SECURITY-ROLE-GATED + audited (AIM-868). Moves
                                    service_identities + device_mappings join keys
                                    from an obsolete device_id to the current one
                                    after re-enroll / stack recreate, so attribution
                                    is not silently orphaned.
- POST /reveal                      SECURITY-ROLE-GATED. Maps a pseudonym back to the
                                    real identity. Every call (allowed or denied)
                                    is written to the audit log with actor+reason.

Authn (AIM-306): the gated endpoints authenticate the caller with a bearer JWT
this service verifies itself (see auth.py). No authorisation decision and no
audit actor ever derives from a client-supplied header. The gate runs BEFORE
request-body validation, so an unauthenticated probe gets a 403 and an audit
row instead of a schema-leaking 422.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import ANONYMOUS_ACTOR, AuthError, Principal, authenticate, verifier_configured
from .config import Settings, get_settings
from .db import AuditLog, DeviceMapping, DirUser, ServiceIdentity, get_session, init_db
from .directory_source import build_source
from .pseudonym import pseudonymize
from .resolver import lookup_service, resolve_identity, resolve_service
from .sync import sync_directory

log = logging.getLogger(__name__)

# AIM-1114: in-process counters for resolve fall-through signals. Exposed on
# GET /metrics (Prometheus text). Process-local; reset on restart — page on
# rate, not absolute value.
_resolve_metrics = {
    "resolve_total": 0,
    "resolve_unresolved_total": 0,
    "resolve_unresolved_missing_device_id_total": 0,
    "resolve_unresolved_service_mapping_miss_total": 0,
}


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    init_db()
    if not verifier_configured(get_settings()):
        # Fail closed AND loud: the gated endpoints deny everything until an
        # operator sets IDENTITY_SYNC_JWT_HS256_SECRET or _JWT_JWKS_URL.
        log.warning(
            "no JWT verifier configured — /reveal, POST /device-mappings and "
            "POST /service-identities will deny every call (set "
            "IDENTITY_SYNC_JWT_HS256_SECRET or IDENTITY_SYNC_JWT_JWKS_URL)"
        )
    yield


app = FastAPI(title="identity-sync", version="0.1.0", lifespan=_lifespan)


class ResolveRequest(BaseModel):
    device_id: str | None = None
    os_user: str | None = None


class ResolveResponse(BaseModel):
    resolution: str
    user_pseudonym: str | None
    team: str | None
    suspended: bool = False
    # "human" | "service" | "unknown" — machine activity stays labelled even when
    # it resolves to a named operator's pseudonym (AIM-149).
    principal_kind: str = "human"
    service_id: str | None = None


SERVICE_KINDS = ("agent_host", "ci_runner", "shared_workstation")


class ServiceIdentityRequest(BaseModel):
    service_id: str = Field(min_length=3, max_length=128, pattern=r"^svc:[a-z0-9][a-z0-9._-]*$")
    kind: str = Field(pattern=r"^(agent_host|ci_runner|shared_workstation)$")
    display_name: str = Field(default="", max_length=256)
    device_id: str | None = Field(default=None, max_length=128)
    os_user: str | None = Field(default=None, max_length=256)
    operator_email: str | None = Field(default=None, max_length=320)
    team: str | None = Field(default=None, max_length=256)
    source: str = Field(default="manual", pattern=r"^(manual|enrollment)$")


class ServiceIdentityResponse(BaseModel):
    service_id: str
    kind: str
    display_name: str
    device_id: str | None
    os_user: str | None
    operator_email: str | None
    team: str | None
    source: str
    user_pseudonym: str


def _service_response(svc: ServiceIdentity, secret: str) -> ServiceIdentityResponse:
    return ServiceIdentityResponse(
        service_id=svc.service_id,
        kind=svc.kind,
        display_name=svc.display_name,
        device_id=svc.device_id,
        os_user=svc.os_user,
        operator_email=svc.operator_email,
        team=svc.team,
        source=svc.source,
        user_pseudonym=pseudonymize(svc.service_id, secret),
    )


DEVICE_MAPPING_SOURCES = ("intune", "collector", "manual", "enrollment")


class DeviceMappingRequest(BaseModel):
    """Bind an enrolled device (or OS user) to a directory human (AIM-455).

    Without rows here the resolver rules 1–2 can never fire and every event
    falls through to unresolved — the 0% attribution failure mode.
    """

    device_id: str | None = Field(default=None, max_length=128)
    os_user: str | None = Field(default=None, max_length=256)
    primary_email: str = Field(min_length=3, max_length=320)
    source: str = Field(default="manual", pattern=r"^(intune|collector|manual|enrollment)$")
    # Binding a device to a person is an attribution decision — same posture
    # as /reveal and service-identity registration.
    reason: str = Field(min_length=10, max_length=1024)


class DeviceMappingResponse(BaseModel):
    id: str
    device_id: str | None
    os_user: str | None
    primary_email: str
    source: str
    user_pseudonym: str
    team: str | None
    updated_at: datetime


class RevealRequest(BaseModel):
    user_pseudonym: str = Field(min_length=3)
    reason: str = Field(min_length=10, max_length=1024)  # justification is mandatory


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    """Prometheus text exposition for resolve fall-through signals (AIM-1114)."""
    lines = [
        "# HELP identity_resolve_total POST /resolve calls.",
        "# TYPE identity_resolve_total counter",
        f"identity_resolve_total {_resolve_metrics['resolve_total']}",
        "# HELP identity_resolve_unresolved_total Resolutions that returned principal_kind=unknown.",
        "# TYPE identity_resolve_unresolved_total counter",
        f"identity_resolve_unresolved_total {_resolve_metrics['resolve_unresolved_total']}",
        "# HELP identity_resolve_unresolved_missing_device_id_total Unresolved resolves with no device_id (service hosts keyed by device_id fall through).",
        "# TYPE identity_resolve_unresolved_missing_device_id_total counter",
        f"identity_resolve_unresolved_missing_device_id_total {_resolve_metrics['resolve_unresolved_missing_device_id_total']}",
        "# HELP identity_resolve_unresolved_service_mapping_miss_total Unresolved while a service_identity fleet exists (missing device_id fall-through) or a device_id row was found after an unresolved result (repair path).",
        "# TYPE identity_resolve_unresolved_service_mapping_miss_total counter",
        f"identity_resolve_unresolved_service_mapping_miss_total {_resolve_metrics['resolve_unresolved_service_mapping_miss_total']}",
    ]
    return "\n".join(lines) + "\n"


@app.post("/sync")
def sync(session: Session = Depends(get_session), settings: Settings = Depends(get_settings)) -> dict:
    return sync_directory(session, build_source(settings))


@app.post("/resolve", response_model=ResolveResponse)
def resolve(
    body: ResolveRequest,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> ResolveResponse:
    r = resolve_identity(
        session,
        device_id=body.device_id,
        os_user=body.os_user,
        pseudonym_secret=settings.pseudonym_secret,
        primary_email_domain=settings.primary_email_domain,
    )
    _resolve_metrics["resolve_total"] += 1
    if r.resolution == "unresolved":
        _resolve_metrics["resolve_unresolved_total"] += 1
        # AIM-1114: never silently absorb fall-through when a service principal
        # is registered for this host. Missing device_id is the dogfood residual
        # (collector attests only os_user; service_identities are device_id-keyed).
        if not body.device_id:
            _resolve_metrics["resolve_unresolved_missing_device_id_total"] += 1
            # Presence of any active service_identity makes this louder: a known
            # service fleet exists and this call could not join it without device_id.
            svc_count = len(session.execute(select(ServiceIdentity)).scalars().all())
            log.warning(
                "resolve unresolved without device_id (os_user_present=%s "
                "service_identities=%d) — registered service hosts will emit "
                "principal_kind=unknown until the collector attests device_id "
                "(AIM-1114)",
                bool(body.os_user),
                svc_count,
            )
            if svc_count > 0:
                # Distinct series so "unresolved while service fleet exists"
                # can alert without inventing an identity for this event.
                _resolve_metrics["resolve_unresolved_service_mapping_miss_total"] += 1
        else:
            # device_id present but unresolved: detect lookup races / orphans.
            orphan = lookup_service(session, device_id=body.device_id, os_user=None)
            if orphan is not None:
                # Should be unreachable if resolve_identity rule 0 is correct;
                # if it fires, repair by returning the service resolution.
                _resolve_metrics["resolve_unresolved_service_mapping_miss_total"] += 1
                log.error(
                    "resolve returned unresolved but service_identity exists "
                    "for device_id (service_id=%s); repairing to service principal "
                    "(AIM-1114)",
                    orphan.service_id,
                )
                r = resolve_service(session, orphan, settings.pseudonym_secret)
    return ResolveResponse(
        resolution=r.resolution,
        user_pseudonym=r.user_pseudonym,
        team=r.team,
        suspended=r.suspended,
        principal_kind=r.principal_kind,
        service_id=r.service_id,
    )


def _audit(
    session: Session,
    *,
    actor: str,
    role: str,
    target: str,
    reason: str,
    outcome: str,
    action: str = "reveal_identity",
) -> None:
    session.add(
        AuditLog(
            actor=actor,
            actor_role=role,
            action=action,
            target_pseudonym=target,
            reason=reason,
            outcome=outcome,
        )
    )
    session.commit()


_bearer = HTTPBearer(auto_error=False)

#: Target recorded for audit rows written before the body is parsed. The gate
#: runs ahead of validation on purpose (AIM-306): authorise first, then parse.
_TARGET_UNPARSED = "(not parsed)"


def _security_gate(action: str):
    """Build the authn+authz dependency for a gated endpoint.

    Declared at decorator level (``dependencies=[Depends(...)]``) so it runs
    BEFORE FastAPI validates the request body — an unauthenticated caller gets
    a 403 and an audit row, never a schema-leaking 422. The endpoint also takes
    the same callable as a parameter dependency; FastAPI caches dependencies
    per request, so the gate executes exactly once.

    Every denial is audited with the *verified* principal — or the explicit
    string ``anonymous`` — never with anything the caller claimed in a header.
    """

    async def _gate(
        request: Request,
        session: Session = Depends(get_session),
        settings: Settings = Depends(get_settings),
    ) -> Principal:
        creds = await _bearer(request)
        try:
            principal = authenticate(creds.credentials if creds else None, settings)
        except AuthError as exc:
            _audit(
                session,
                actor=ANONYMOUS_ACTOR,
                role="",
                target=_TARGET_UNPARSED,
                reason=str(exc),
                outcome="denied",
                action=action,
            )
            raise HTTPException(status_code=403, detail="a verified bearer token is required") from exc
        if settings.reveal_role not in principal.groups:
            _audit(
                session,
                actor=principal.actor,
                role=principal.role_for_audit,
                target=_TARGET_UNPARSED,
                reason=f"caller lacks the {settings.reveal_role} role",
                outcome="denied",
                action=action,
            )
            raise HTTPException(
                status_code=403, detail=f"requires the {settings.reveal_role} role"
            )
        return principal

    return _gate


_gate_reveal = _security_gate("reveal_identity")
_gate_register = _security_gate("register_service_identity")
_gate_device_mapping = _security_gate("register_device_mapping")
_gate_rebind = _security_gate("rebind_device_join_keys")


def _device_mapping_response(
    mapping: DeviceMapping, secret: str, session: Session
) -> DeviceMappingResponse:
    user = session.execute(
        select(DirUser).where(DirUser.primary_email == mapping.primary_email.lower())
    ).scalar_one_or_none()
    return DeviceMappingResponse(
        id=mapping.id,
        device_id=mapping.device_id,
        os_user=mapping.os_user,
        primary_email=mapping.primary_email,
        source=mapping.source,
        user_pseudonym=pseudonymize(mapping.primary_email, secret),
        team=user.team if user else None,
        updated_at=mapping.updated_at or datetime.now(timezone.utc),
    )


def _find_mapping(
    session: Session, *, device_id: str | None, os_user: str | None
) -> DeviceMapping | None:
    """Locate an existing mapping to upsert. Prefer device_id (authoritative)."""
    if device_id:
        hit = session.execute(
            select(DeviceMapping).where(DeviceMapping.device_id == device_id)
        ).scalar_one_or_none()
        if hit:
            return hit
    if os_user:
        return session.execute(
            select(DeviceMapping).where(DeviceMapping.os_user == os_user)
        ).scalar_one_or_none()
    return None


@app.get("/device-mappings", response_model=list[DeviceMappingResponse])
def list_device_mappings(
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> list[DeviceMappingResponse]:
    """Join keys currently in force. Emails stay inside identity-sync."""
    rows = session.execute(select(DeviceMapping)).scalars().all()
    return [_device_mapping_response(m, settings.pseudonym_secret, session) for m in rows]


@app.post(
    "/device-mappings",
    response_model=DeviceMappingResponse,
    dependencies=[Depends(_gate_device_mapping)],
)
def upsert_device_mapping(
    body: DeviceMappingRequest,
    principal: Principal = Depends(_gate_device_mapping),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> DeviceMappingResponse:
    """Bind a device (or OS user) to a directory human. Role-gated + audited.

    AIM-455: enroll alone only mints a device token. This endpoint is the
    missing write path that populates ``device_mappings`` so resolver rules
    1–2 can fire. The email must already exist in ``dir_users`` — we refuse
    to invent identities that are not in the directory of record.
    """
    if not body.device_id and not body.os_user:
        raise HTTPException(
            status_code=422,
            detail="device mapping needs at least one join key (device_id or os_user)",
        )

    email = body.primary_email.strip().lower()
    user = session.execute(
        select(DirUser).where(DirUser.primary_email == email)
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=422,
            detail="primary_email is not in the directory; sync the directory first",
        )

    mapping = _find_mapping(session, device_id=body.device_id, os_user=body.os_user)
    if mapping is None:
        mapping = DeviceMapping(
            device_id=body.device_id,
            os_user=body.os_user,
            primary_email=email,
            source=body.source,
        )
        session.add(mapping)
    else:
        # Upsert in place so re-enroll / admin corrections leave one row per key.
        if body.device_id:
            mapping.device_id = body.device_id
        if body.os_user:
            mapping.os_user = body.os_user
        mapping.primary_email = email
        mapping.source = body.source
        mapping.updated_at = datetime.now(timezone.utc)
    session.commit()

    target = body.device_id or body.os_user or email
    _audit(
        session,
        actor=principal.actor,
        role=principal.role_for_audit,
        target=str(target),
        reason=body.reason,
        outcome="allowed",
        action="register_device_mapping",
    )
    return _device_mapping_response(mapping, settings.pseudonym_secret, session)


class RebindDeviceRequest(BaseModel):
    """Move identity-sync join keys when an enrolled device_id changes (AIM-868).

    Dogfood failure mode: identity-data volume keeps service_identities while
    ingest's devices table is recreated; re-enroll mints a new device_id and
    the declared service principal stays bound to the obsolete id. Attribution
    collapses to unresolved until an operator rebinds by hand.
    """

    from_device_id: str = Field(min_length=1, max_length=128)
    to_device_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=10, max_length=1024)


class RebindDeviceResponse(BaseModel):
    from_device_id: str
    to_device_id: str
    service_identities_updated: int
    device_mappings_updated: int


@app.post(
    "/join-keys/rebind-device",
    response_model=RebindDeviceResponse,
    dependencies=[Depends(_gate_rebind)],
)
def rebind_device_join_keys(
    body: RebindDeviceRequest,
    principal: Principal = Depends(_gate_rebind),
    session: Session = Depends(get_session),
) -> RebindDeviceResponse:
    """Point every join key that used ``from_device_id`` at ``to_device_id``.

    Idempotent: when the ids are equal, no rows change. Does not invent new
    service principals or directory users — only rewires existing keys.
    """
    from_id = body.from_device_id.strip()
    to_id = body.to_device_id.strip()
    if not from_id or not to_id:
        raise HTTPException(status_code=422, detail="from_device_id and to_device_id are required")
    if from_id == to_id:
        return RebindDeviceResponse(
            from_device_id=from_id,
            to_device_id=to_id,
            service_identities_updated=0,
            device_mappings_updated=0,
        )

    svc_rows = (
        session.execute(select(ServiceIdentity).where(ServiceIdentity.device_id == from_id))
        .scalars()
        .all()
    )
    for svc in svc_rows:
        svc.device_id = to_id
        svc.updated_at = datetime.now(timezone.utc)

    map_rows = (
        session.execute(select(DeviceMapping).where(DeviceMapping.device_id == from_id))
        .scalars()
        .all()
    )
    for mapping in map_rows:
        mapping.device_id = to_id
        mapping.updated_at = datetime.now(timezone.utc)

    session.commit()

    _audit(
        session,
        actor=principal.actor,
        role=principal.role_for_audit,
        target=f"{from_id}->{to_id}",
        reason=body.reason,
        outcome="allowed",
        action="rebind_device_join_keys",
    )
    return RebindDeviceResponse(
        from_device_id=from_id,
        to_device_id=to_id,
        service_identities_updated=len(svc_rows),
        device_mappings_updated=len(map_rows),
    )


@app.get("/service-identities", response_model=list[ServiceIdentityResponse])
def list_service_identities(
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> list[ServiceIdentityResponse]:
    """Declared non-human hosts. No personal data beyond the operator email,
    which is what makes the mapping auditable in the first place."""
    rows = session.execute(select(ServiceIdentity)).scalars().all()
    return [_service_response(s, settings.pseudonym_secret) for s in rows]


@app.post("/service-identities", response_model=ServiceIdentityResponse, dependencies=[Depends(_gate_register)])
def upsert_service_identity(
    body: ServiceIdentityRequest,
    principal: Principal = Depends(_gate_register),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> ServiceIdentityResponse:
    """Declare a host non-human. Role-gated and audited in both directions.

    Naming an ``operator_email`` routes that host's AI-tool usage to a named
    person, so this is an identity-attribution decision, not configuration:
    every attempt is written to the same append-only log as a reveal, with the
    verified JWT principal as the actor.
    """
    if not body.device_id and not body.os_user:
        raise HTTPException(
            status_code=422, detail="service identity needs at least one join key (device_id or os_user)"
        )

    svc = session.get(ServiceIdentity, body.service_id)
    if svc is None:
        svc = ServiceIdentity(service_id=body.service_id)
        session.add(svc)
    svc.kind = body.kind
    svc.display_name = body.display_name
    svc.device_id = body.device_id
    svc.os_user = body.os_user
    svc.operator_email = body.operator_email.lower() if body.operator_email else None
    svc.team = body.team
    svc.source = body.source
    session.commit()

    _audit(
        session,
        actor=principal.actor,
        role=principal.role_for_audit,
        target=body.service_id,
        reason=(
            f"register service identity ({body.kind}); operator="
            f"{svc.operator_email or 'none'}"
        ),
        outcome="allowed",
        action="register_service_identity",
    )
    return _service_response(svc, settings.pseudonym_secret)


@app.post("/reveal", dependencies=[Depends(_gate_reveal)])
def reveal(
    body: RevealRequest,
    principal: Principal = Depends(_gate_reveal),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict:
    # The gate has already authenticated + authorised the caller and audited
    # any denial. Every allowed attempt is audited below with the verified
    # principal as actor — denied attempts are a detection signal.

    # Compare by recomputing pseudonyms of directory users (the DB never stores
    # pseudonym->email mappings; that join must stay expensive and access-gated).
    users = session.execute(select(DirUser)).scalars().all()
    match = next(
        (u for u in users if pseudonymize(u.primary_email, settings.pseudonym_secret) == body.user_pseudonym),
        None,
    )
    # A service pseudonym has no directory user behind it. Answering "unknown"
    # would be wrong — we know exactly what it is, and the analyst asking is
    # entitled to hear "this is a machine" instead of hitting a dead end.
    svc = None
    if match is None:
        services = session.execute(select(ServiceIdentity)).scalars().all()
        svc = next(
            (s for s in services if pseudonymize(s.service_id, settings.pseudonym_secret) == body.user_pseudonym),
            None,
        )
    _audit(
        session,
        actor=principal.actor,
        role=principal.role_for_audit,
        target=body.user_pseudonym,
        reason=body.reason,
        outcome="allowed" if (match or svc) else "denied",
    )
    if svc is not None:
        return {
            "principal_kind": "service",
            "service_id": svc.service_id,
            "kind": svc.kind,
            "display_name": svc.display_name,
            "operator_email": svc.operator_email,
            "team": svc.team,
        }
    if match is None:
        raise HTTPException(status_code=404, detail="no directory user matches this pseudonym")
    return {
        "principal_kind": "human",
        "primary_email": match.primary_email,
        "full_name": match.full_name,
        "team": match.team,
        "org_unit_path": match.org_unit_path,
        "suspended": match.suspended,
    }
