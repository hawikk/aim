"""Env-driven settings (SHADOW_AI_* prefix)."""

from __future__ import annotations

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Docker image WORKDIR + Dockerfile COPY of catalogue/fixtures.
_CONTAINER_DATA_ROOT = Path("/app")


def resolve_data_path(
    *parts: str,
    file_anchor: Path | None = None,
    app_root: Path = _CONTAINER_DATA_ROOT,
) -> Path:
    """Resolve catalogue/fixture paths for editable *and* installed layouts.

    After ``pip install`` in the Docker image, ``__file__`` lives under
    ``site-packages/shadow_ai/``, so ``parents[2]`` is
    ``/usr/local/lib/python3.12`` — not ``/app`` where the image copies
    catalogue/fixtures and where compose bind-mounts them (AIM-1032).

    Prefer an existing file under (1) the container data root, then
    (2) the editable/source-tree service root (``parents[2]`` of this
    module). Fall back to the container path when ``/app`` data dirs
    exist, else the source-tree path (clearer local error messages).
    """
    here = (file_anchor or Path(__file__)).resolve()
    source_root = here.parents[2]
    candidates = (
        app_root.joinpath(*parts),
        source_root.joinpath(*parts),
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    if (app_root / "catalogue").is_dir() or (app_root / "fixtures").is_dir():
        return app_root.joinpath(*parts)
    return source_root.joinpath(*parts)


_DEFAULT_CATALOGUE = resolve_data_path("catalogue", "ai-tools.json")
_DEFAULT_FIXTURE = resolve_data_path("fixtures", "oauth_grants.json")
_DEFAULT_PROXY_FIXTURE = resolve_data_path("fixtures", "proxy_observations.json")
_DEFAULT_PROCESS_FIXTURE = resolve_data_path("fixtures", "process_observations.json")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SHADOW_AI_")

    database_url: str = "sqlite:///./shadow_ai.db"
    catalogue_path: str = str(_DEFAULT_CATALOGUE)

    # Same value as IDENTITY_SYNC_PSEUDONYM_SECRET in prod so grant
    # pseudonyms join with event pseudonyms. Dev default is explicit and
    # must never ship to prod.
    pseudonym_secret: str = "dev-only-shadow-ai-secret"

    # IdP OAuth grant source: fixture | google | entra | okta | multi.
    grant_source: str = "fixture"
    grant_fixture_path: str = str(_DEFAULT_FIXTURE)
    # For grant_source=multi: comma-separated list, e.g. "fixture,entra".
    grant_sources: str = ""

    # Google Workspace Reports API
    google_credentials_file: str = ""
    google_delegated_admin: str = ""

    # Microsoft Entra ID (MS Graph client-credentials)
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""

    # Okta
    okta_org_url: str = ""
    okta_api_token: str = ""

    # Proxy corroboration signal: fixture (dev/test) | postgres (prod).
    proxy_source: str = "fixture"
    proxy_fixture_path: str = str(_DEFAULT_PROXY_FIXTURE)
    # In prod this points at the ingest event store (read-only user).
    events_database_url: str = ""

    # Process/binary signal for coding-tool auto-discovery (AIM-644):
    # fixture | postgres | none.
    process_source: str = "fixture"
    process_fixture_path: str = str(_DEFAULT_PROCESS_FIXTURE)

    # Retention (AIM-300 privacy boundary): revoked grants are purged this
    # many days after their last sighting. Active grants persist while active.
    revoked_retention_days: int = 90

    # When true, also upsert into platform findings table (Postgres dogfood).
    emit_platform_findings: bool = True

    host: str = "0.0.0.0"
    port: int = 8090

    @field_validator("database_url", "events_database_url")
    @classmethod
    def _normalize_pg_scheme(cls, value: str) -> str:
        # SQLAlchemy 1.4+/2.0 dropped the legacy `postgres://` scheme alias;
        # create_engine() then raises NoSuchModuleError. Coerce it to the
        # canonical `postgresql://` so every consumer (env, compose default,
        # sqlite fallback) yields a driver SQLAlchemy can load.
        # (AIM-1061)
        if value.startswith("postgres://"):
            return "postgresql://" + value[len("postgres://") :]
        return value
