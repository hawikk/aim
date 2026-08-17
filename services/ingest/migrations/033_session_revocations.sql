-- 033_session_revocations.sql — server-side session revoke watermarks.
-- 033_session_revocations.sql — server-side session revoke watermarks.
--
-- Stateless HMAC session cookies embed role at login. Without a server check,
-- a leaver keeps access until AIM_SESSION_TTL_HOURS. This table stores the
-- latest force-deny watermark per email:
--
--   * Any session with iat <= extract(epoch from revoked_at) is denied.
--   * A successful re-login after re-provision issues iat > watermark and works.
--   * Writers: human admin playbook, or identity-sync deprovision automation
-- (POST /api/admin/sessions/revoke via service token).
-- * Full SCIM User lifecycle remains optional product work.
--   * SCIM User lifecycle is still not implemented; operators (or future
--     automation) call POST /api/admin/sessions/revoke.
--
-- API process keeps an in-memory cache (apps/api/src/session-revocation.js)
-- and write-through upserts here so restarts retain leaver denials.

CREATE TABLE IF NOT EXISTS session_revocations (
  email       TEXT PRIMARY KEY,           -- lowercased identity email
  revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_by  TEXT,                       -- admin actor email (audit mirror)
  reason      TEXT                        -- free-text, max enforced in API
);

-- Operator / incident queries: newest revokes first.
CREATE INDEX IF NOT EXISTS idx_session_revocations_revoked_at
  ON session_revocations (revoked_at DESC);
