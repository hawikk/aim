"""Environment-driven configuration. No secrets in code; all via env vars."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDENTITY_SYNC_", env_file=".env", extra="ignore")

    # SQLAlchemy URL. Dev default is local SQLite; prod uses managed Postgres.
    database_url: str = "sqlite:///./identity_sync.db"

    # Directory source: "fixture" (dev/test, reads fixture_dir) or "google" (Admin SDK).
    directory_source: str = "fixture"
    fixture_dir: str = "fixtures"

    # Google Admin SDK settings (directory_source=google).
    google_service_account_file: str = ""  # path to SA JSON key with domain-wide delegation
    google_admin_subject: str = ""  # admin user the SA impersonates
    google_customer_id: str = "my_customer"

    # HMAC key for pseudonymization. MUST come from a secret manager in prod.
    # Rotating this key rewrites every pseudonym — treat as a deliberate re-key event.
    pseudonym_secret: str = "dev-only-insecure-pseudonym-secret"

    # Reveal grant (AIM-302 §1 / AIM-384): the IdP group (JWT `groups` claim,
    # minted by the platform IdP) whose members may reveal user-level identity.
    # Aligned with apps/api AIM_REVEAL_GROUPS — same grant name in both places.
    # Everything else sees team-level data only.
    reveal_role: str = "ai-monitoring-revealers"

    # Caller authentication for the gated endpoints (AIM-306). The caller proves
    # identity with a bearer JWT this service verifies — never with headers.
    # Two verifier paths, either is sufficient, both fail closed when absent:
    # - jwt_hs256_secret: shared secret for in-network/service callers and dev.
    # - jwt_jwks_url:     platform IdP JWKS endpoint (prod; RS/ES keys).
    jwt_hs256_secret: str = ""
    jwt_jwks_url: str = ""
    # Optional claim pinning. Empty = not checked.
    jwt_issuer: str = ""
    jwt_audience: str = ""

    # Domain used when a bare OS username must be expanded to an email (fallback join key).
    primary_email_domain: str = "example.com"

    # AIM-714: auto force-deny live AIM SSO sessions when a directory user is
    # newly suspended / missing. Both must be set; otherwise sync still
    # updates dir_users and skips the platform revoke (opt-in).
    # The bearer must be a service token whose name is listed in the API's
    # AIM_SESSION_REVOKE_SERVICES (service tokens cannot hold admin).
    aim_api_url: str = ""  # e.g. http://api:8080
    session_revoke_token: str = ""  # raw bearer for the identity-sync service token


@lru_cache
def get_settings() -> Settings:
    return Settings()
