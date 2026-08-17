"""Identity resolution: map endpoint/collector identity to a directory user.

Join-key decision (see docs/identity-mapping-design.md, ADR-001):
  0. device_id / os_user -> service_identities (non-human hosts)
  1. device_id  -> device_mappings (Intune enrollment, authoritative)
  2. os_user    -> device_mappings (collector-reported hint)
  3. os_user@primary_email_domain -> dir_users (bare-username heuristic)
  4. unresolved -> event is still accepted with user_pseudonym=None and
     resolution="unresolved" so it counts toward "unattributed usage" metrics
     rather than silently dropping.

Rule 0 runs FIRST on purpose. A declared non-human host must never fall through
to the bare-username heuristic, which would guess a person from the OS login and
attribute autonomous machine activity to whoever happens to share that name.

Every resolution carries a ``principal_kind`` — "human" or "service" — so a
service-attributed event stays distinguishable downstream even when it resolves
to the operator's pseudonym. Without that label, "map the agent host to its
operator" is indistinguishable from "that engineer typed this".

The resolver returns the pseudonym + team for the event store — never the email.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .db import DeviceMapping, DirUser, ServiceIdentity
from .pseudonym import pseudonymize


@dataclass
class Resolution:
    # "device_id" | "os_user" | "email_heuristic" | "service_operator"
    # | "service_identity" | "unresolved"
    resolution: str
    user_pseudonym: str | None
    team: str | None
    suspended: bool = False
    principal_kind: str = "human"  # "human" | "service" | "unknown"
    service_id: str | None = None


def _resolve_email(session: Session, email: str, secret: str) -> Resolution | None:
    user = session.execute(
        select(DirUser).where(DirUser.primary_email == email.lower())
    ).scalar_one_or_none()
    if user is None:
        return None
    return Resolution(
        resolution="",  # filled by caller
        user_pseudonym=pseudonymize(user.primary_email, secret),
        team=user.team,
        suspended=user.suspended,
    )


def lookup_service(
    session: Session, *, device_id: str | None, os_user: str | None
) -> ServiceIdentity | None:
    """Return the matching service_identity row, or None.

    Public so the /resolve HTTP layer can re-check after an unresolved result
    (repair + metric path) without re-implementing join rules.
    """
    clauses = []
    if device_id:
        clauses.append(ServiceIdentity.device_id == device_id)
    if os_user:
        clauses.append(ServiceIdentity.os_user == os_user)
    if not clauses:
        return None
    # device_id is the stronger key, so prefer a device_id hit when both match.
    rows = session.execute(select(ServiceIdentity).where(or_(*clauses))).scalars().all()
    if not rows:
        return None
    if device_id:
        for row in rows:
            if row.device_id == device_id:
                return row
    return rows[0]


# Back-compat alias for internal callers/tests that used the private name.
_lookup_service = lookup_service


def resolve_service(
    session: Session, svc: ServiceIdentity, secret: str
) -> Resolution:
    """Service principal, attributed to its operator when one is known."""
    if svc.operator_email:
        operator = _resolve_email(session, svc.operator_email, secret)
        if operator:
            operator.resolution = "service_operator"
            operator.principal_kind = "service"
            operator.service_id = svc.service_id
            # The host's team wins when set: an agent host belongs to the team
            # that runs it, not necessarily to the operator's own team.
            operator.team = svc.team or operator.team
            return operator
        # Operator named but absent from the directory (left the company, typo,
        # directory not synced). Fall back to the service principal rather than
        # inventing an identity — a wrong name is worse than a machine name.
    return Resolution(
        resolution="service_identity",
        user_pseudonym=pseudonymize(svc.service_id, secret),
        team=svc.team,
        principal_kind="service",
        service_id=svc.service_id,
    )


_resolve_service = resolve_service


def resolve_identity(
    session: Session,
    *,
    device_id: str | None,
    os_user: str | None,
    pseudonym_secret: str,
    primary_email_domain: str,
) -> Resolution:
    # 0. Declared non-human host -> service principal (never the heuristic).
    svc = _lookup_service(session, device_id=device_id, os_user=os_user)
    if svc:
        return _resolve_service(session, svc, pseudonym_secret)

    # 1. Intune-enrolled device -> enrolled user.
    if device_id:
        mapping = session.execute(
            select(DeviceMapping).where(DeviceMapping.device_id == device_id)
        ).scalar_one_or_none()
        if mapping:
            r = _resolve_email(session, mapping.primary_email, pseudonym_secret)
            if r:
                r.resolution = "device_id"
                return r

    # 2. Collector-reported OS user -> known mapping.
    if os_user:
        mapping = session.execute(
            select(DeviceMapping).where(DeviceMapping.os_user == os_user)
        ).scalar_one_or_none()
        if mapping:
            r = _resolve_email(session, mapping.primary_email, pseudonym_secret)
            if r:
                r.resolution = "os_user"
                return r

        # 3. Bare username heuristic: jdoe / DOMAIN\jdoe -> jdoe@corp-domain.
        if "\\" in os_user:
            os_user = os_user.split("\\", 1)[1]  # DOMAIN\jdoe -> jdoe
        candidate = os_user if "@" in os_user else f"{os_user}@{primary_email_domain}"
        r = _resolve_email(session, candidate, pseudonym_secret)
        if r:
            r.resolution = "email_heuristic"
            return r

    return Resolution(
        resolution="unresolved",
        user_pseudonym=None,
        team=None,
        principal_kind="unknown",
    )
