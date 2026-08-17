"""Storage: SQLAlchemy models for shadow-AI discovery.

Table DDL also lives in services/ingest/migrations/026_shadow_ai.sql (the
platform norm for Postgres queryable data, applied at ingest boot). These
models mirror it so dev/test can create_all against SQLite. Keep the two in
sync — same columns, same constraints.

Privacy (boundary):
- user_pseudonym is u_<hmac> from the shared HMAC secret, never an email.
- scopes are OAuth scope URIs (metadata), never content.
- No URLs beyond domain level, no request content, anywhere in this subsystem.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def aware(dt: datetime) -> datetime:
    """SQLite drops tzinfo on read; treat naive values as UTC everywhere."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class OAuthGrant(Base):
    __tablename__ = "shadow_ai_grants"
    __table_args__ = (
        UniqueConstraint("user_pseudonym", "idp_source", "app_name", name="uq_grant_identity_app"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_pseudonym: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    idp_source: Mapped[str] = mapped_column(Text, nullable=False)
    client_id: Mapped[str | None] = mapped_column(Text)
    app_name: Mapped[str] = mapped_column(Text, nullable=False)
    scopes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_action: Mapped[str] = mapped_column(String(16), nullable=False)  # authorize | revoke
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class ToolInventoryRow(Base):
    __tablename__ = "shadow_ai_tools"

    tool_id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    vendor: Mapped[str | None] = mapped_column(Text)
    catalogued: Mapped[bool] = mapped_column(Boolean, nullable=False)
    sanctioned: Mapped[bool | None] = mapped_column(Boolean)  # NULL when uncatalogued
    data_access_class: Mapped[str | None] = mapped_column(Text)
    sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    attribution: Mapped[str] = mapped_column(Text, nullable=False)  # attributed|unattributed|partial
    identity_count: Mapped[int | None] = mapped_column(Integer)
    scopes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    scope_classes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_band: Mapped[str] = mapped_column(Text, nullable=False)
    risk_components: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class GrantFinding(Base):
    """Materialized unapproved_ai_saas_grant rows. Pseudonym only."""

    __tablename__ = "shadow_ai_findings"

    finding_id: Mapped[str] = mapped_column(Text, primary_key=True)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False, default="unapproved_ai_saas_grant")
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    user_pseudonym: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    app_name: Mapped[str] = mapped_column(Text, nullable=False)
    tool_id: Mapped[str | None] = mapped_column(Text)
    client_id: Mapped[str | None] = mapped_column(Text)
    idp_source: Mapped[str] = mapped_column(Text, nullable=False)
    scopes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sanctioned: Mapped[bool | None] = mapped_column(Boolean)
    catalogued: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )



class CodingDiscoveryFinding(Base):
    """Materialized unknown_ai_coding_tool rows. Discovery only.

    Separate from grant findings so sync/persist of each rule_id cannot
    clobber the other. Analyst disposition is on platform ``findings``.
    """

    __tablename__ = "shadow_ai_coding_discoveries"

    finding_id: Mapped[str] = mapped_column(Text, primary_key=True)
    rule_id: Mapped[str] = mapped_column(
        Text, nullable=False, default="unknown_ai_coding_tool"
    )
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    signal_source: Mapped[str] = mapped_column(Text, nullable=False)  # idp_oauth|proxy_domain|process
    signal_value: Mapped[str] = mapped_column(Text, nullable=False)
    tool_slug: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    matched_patterns: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    strength: Mapped[str] = mapped_column(Text, nullable=False)  # strong|weak
    identity_count: Mapped[int | None] = mapped_column(Integer)
    host_count: Mapped[int | None] = mapped_column(Integer)
    event_count: Mapped[int | None] = mapped_column(Integer)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


# Discovery-queue statuses (migration 027).
DISCOVERY_STATUSES = frozenset(
    {"open", "proposed", "catalogued", "dismissed", "known_non_ai"}
)
DISCOVERY_OPEN_STATUSES = frozenset({"open", "proposed"})
DISCOVERY_TRANSITIONS = {
    "open": frozenset({"proposed", "catalogued", "dismissed", "known_non_ai"}),
    "proposed": frozenset({"open", "catalogued", "dismissed", "known_non_ai"}),
    "catalogued": frozenset({"open", "proposed"}),  # reopen if catalogue PR reverts
    "dismissed": frozenset({"open", "proposed"}),
    "known_non_ai": frozenset({"open", "proposed"}),
}


class DiscoveryQueueRow(Base):
    """Uncatalogued IdP apps waiting for a catalogue PR.

    Table DDL: services/ingest/migrations/034_shadow_ai_ops.sql.
    Privacy: app names + client ids + identity counts only — no emails.
    """

    __tablename__ = "shadow_ai_discovery_queue"
    __table_args__ = (
        UniqueConstraint("app_name", "client_id", name="uq_discovery_app_client"),
    )

    queue_id: Mapped[str] = mapped_column(Text, primary_key=True)
    app_name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # Empty string when the IdP grant had no client_id — keeps UNIQUE stable
    # across SQLite and Postgres (NULL is not equal to NULL in UNIQUE).
    client_id: Mapped[str] = mapped_column(Text, nullable=False, default="")
    idp_sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    identity_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    grant_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    proposed_tool_id: Mapped[str | None] = mapped_column(Text)
    proposed_entry: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="open")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class Disposition(Base):
    """Append-only analyst disposition on a finding / app / tool.

    Postgres enforces append-only via trigger (migration 027). SQLite unit
    tests only INSERT. Active disposition = latest row per
    (target_kind, target_key) by created_at.
    """

    __tablename__ = "shadow_ai_dispositions"

    disposition_id: Mapped[str] = mapped_column(Text, primary_key=True)
    target_kind: Mapped[str] = mapped_column(Text, nullable=False)  # finding|app|tool
    target_key: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    # allow | watch | propose_enforce | known_non_ai | catalogue
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    finding_id: Mapped[str | None] = mapped_column(Text)
    app_name: Mapped[str | None] = mapped_column(Text)
    tool_id: Mapped[str | None] = mapped_column(Text)
    client_id: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
