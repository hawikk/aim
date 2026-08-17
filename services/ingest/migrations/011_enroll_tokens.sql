-- 011_enroll_tokens.sql — admin-minted, scoped enrollment tokens.
--
-- Replaces the hand-edited ENROLL_TOKENS env var (docker-compose.yml) with a
-- DB-backed onboarding flow. The dashboard (security-admin only) mints named,
-- scoped, revocable enrollment tokens; POST /v1/enroll redeems them (contract:
-- docs/deployment/enrollment-and-heartbeat.md) alongside the legacy env path,
-- which stays for dev compose and logs a deprecation warning.
--
-- Security posture (same class as the ingest bearer token and per-device
-- token, migration 004):
--   * The token is NEVER stored in cleartext — only its SHA-256 hash is
--     persisted (token_hash). It is returned to the admin exactly once, at
--     mint time, and never logged in full.
--   * token_prefix is a short, non-secret display hint (first 8 chars of the
--     token) so an admin can recognize a token in the list without the secret.
--   * Enrollment-only: these tokens authenticate POST /v1/enroll and nothing
--     else. They cannot post events (/v1/events uses INGEST_TOKENS) — a leaked
--     enroll token can register a device but cannot inject telemetry.
--   * Scope: expires_at (NULL = no expiry) and max_enrollments (NULL =
--     unlimited) bound the blast radius of a leaked token. enrollment_count
--     tracks devices actually registered with it.
--   * Revocation (revoked_at) blocks new enrollments immediately without
--     touching already-issued per-device tokens (device blast radius
--     unchanged — revoking a mint token never de-enrolls its devices).
-- * Every mint/revoke is recorded in the immutable audit trail by
--     the API, with actor identity (created_by / revoked_by mirror it here).

CREATE TABLE IF NOT EXISTS enroll_tokens (
  id                UUID PRIMARY KEY,
  name              TEXT NOT NULL,
  token_hash        TEXT NOT NULL UNIQUE,
  token_prefix      TEXT NOT NULL,
  expires_at        TIMESTAMPTZ,
  max_enrollments   INTEGER,
  enrollment_count  INTEGER NOT NULL DEFAULT 0,
  created_by        TEXT NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at      TIMESTAMPTZ,
  revoked_at        TIMESTAMPTZ,
  revoked_by        TEXT
);

-- /v1/enroll redeems by hash on every non-legacy enrollment.
CREATE INDEX IF NOT EXISTS idx_enroll_tokens_token_hash ON enroll_tokens (token_hash);
-- The dashboard lists newest-first.
CREATE INDEX IF NOT EXISTS idx_enroll_tokens_created_at ON enroll_tokens (created_at);
