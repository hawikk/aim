"""Storage layer: directory reference data, device->user mappings, audit log.

Tables:
- dir_org_units: Google Workspace org units (teams roll up from the OU path).
- dir_users:     directory users with their OU and team attribution.
- device_mappings: endpoint identity (device id / hostname / OS user) -> directory user.
- service_identities: non-human hosts (agent hosts, CI runners) -> service principal,
  with an optional accountable operator.
- audit_log:     immutable record of every user-level identity reveal.

Design note: real emails live ONLY in this service's database. Events and dashboards
carry HMAC pseudonyms (see pseudonym.py). Access to these tables is restricted to
this service; the reveal API is the only read path for user-level identity.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import get_settings


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class DirOrgUnit(Base):
    __tablename__ = "dir_org_units"

    org_unit_path: Mapped[str] = mapped_column(String(512), primary_key=True)  # e.g. "/Engineering/Platform"
    name: Mapped[str] = mapped_column(String(256))
    parent_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Team attribution: top-level segment under "/" ("/Engineering/Platform" -> "Engineering").
    team: Mapped[str] = mapped_column(String(256), index=True)
    last_synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class DirUser(Base):
    __tablename__ = "dir_users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # Google directory user id
    primary_email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(256), default="")
    org_unit_path: Mapped[str] = mapped_column(String(512), index=True)
    team: Mapped[str] = mapped_column(String(256), index=True)  # derived from OU at sync time
    suspended: Mapped[bool] = mapped_column(default=False)
    last_synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class DeviceMapping(Base):
    """Join table between endpoint telemetry identity and directory users.

    Sources, in trust order: Intune enrollment (device_id -> enrolled user) is
    authoritative; os_user mappings are collector-reported hints.
    """

    __tablename__ = "device_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    os_user: Mapped[str | None] = mapped_column(String(256), index=True, nullable=True)
    primary_email: Mapped[str] = mapped_column(String(320), index=True)
    source: Mapped[str] = mapped_column(String(32))  # "intune" | "collector" | "manual"
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class ServiceIdentity(Base):
    """Non-human host -> service principal (ADR identity-source-of-record).

    Agent hosts, CI runners and shared build boxes generate real AI-tool usage
    that belongs to no single person. Without a row here the bare-username
    heuristic is free to guess a human from the OS login, which is the wrong
    fix: it attributes autonomous machine activity to a named employee.

    Security decision on: use both principals — attribute to the
    ``operator_email`` when the accountable operator is known, and to the
    service principal itself when it is not. Either way the resolution is
    labelled ``principal_kind="service"`` so machine activity is never
    indistinguishable from a person at a keyboard.
    """

    __tablename__ = "service_identities"

    service_id: Mapped[str] = mapped_column(String(128), primary_key=True)  # e.g. "svc:agent-host-01"
    display_name: Mapped[str] = mapped_column(String(256), default="")
    kind: Mapped[str] = mapped_column(String(32))  # "agent_host" | "ci_runner" | "shared_workstation"
    device_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    os_user: Mapped[str | None] = mapped_column(String(256), index=True, nullable=True)
    # The accountable human, when one is known. NULL means "nobody owns this
    # host individually" — an honest gap, not a placeholder to fill in later.
    operator_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    team: Mapped[str | None] = mapped_column(String(256), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="manual")  # "manual" | "enrollment"
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class AuditLog(Base):
    """Immutable audit record. Append-only; no update/delete paths exist in the API."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(320))  # who performed the action
    actor_role: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))  # e.g. "reveal_identity"
    target_pseudonym: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(String(1024))
    outcome: Mapped[str] = mapped_column(String(32))  # "allowed" | "denied"


_db_url = get_settings().database_url
_engine_kwargs: dict = {"future": True}
if _db_url.startswith("sqlite"):
    # check_same_thread for the dev server; StaticPool keeps in-memory SQLite
    # on one connection so the schema/data survive across sessions (dev/test only).
    from sqlalchemy.pool import StaticPool

    _engine_kwargs["connect_args"] = {"check_same_thread": False}
    if _db_url in ("sqlite://", "sqlite:///:memory:"):
        _engine_kwargs["poolclass"] = StaticPool

engine = create_engine(_db_url, **_engine_kwargs)
SessionLocal = sessionmaker(engine, expire_on_commit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_session():
    """FastAPI dependency."""
    with SessionLocal() as session:
        yield session
