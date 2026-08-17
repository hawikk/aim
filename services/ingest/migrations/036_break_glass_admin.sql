-- 036_break_glass_admin.sql — AIM-719: emergency admin break-glass
-- dual control + hardware-key (WebAuthn-compatible) with full audit.
--
-- Product path for IdP outage / emergency elevation. Complements the
-- operational runbook (docs/deployment/sso-break-glass.md) so operators do
-- not flip AIM_REQUIRE_SSO=0 or AIM_AUTH_DEV.
--
-- Default: feature gated by AIM_BREAK_GLASS_ADMIN=1 (API refuses when off).
-- Privacy: emails + operator notes only; no session secrets in rows.
-- activation_token_hash is one-way; plaintext token returned once on second approve.

CREATE TABLE IF NOT EXISTS break_glass_admin_principals (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL
                CHECK (email <> '' AND char_length(email) <= 320),
  display_name  TEXT
                CHECK (display_name IS NULL OR char_length(display_name) <= 256),
  enabled       BOOLEAN NOT NULL DEFAULT true,
  created_by    TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  disabled_by   TEXT,
  disabled_at   TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS break_glass_admin_principals_email_uidx
  ON break_glass_admin_principals (lower(email));

COMMENT ON TABLE break_glass_admin_principals IS
  'AIM-719 pre-staged identities eligible for emergency admin (dual control / WebAuthn).';

CREATE TABLE IF NOT EXISTS break_glass_admin_webauthn (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id    UUID NOT NULL REFERENCES break_glass_admin_principals(id) ON DELETE CASCADE,
  credential_id   TEXT NOT NULL
                  CHECK (credential_id <> '' AND char_length(credential_id) <= 512),
  -- EC P-256 public key as JWK JSON (kty=EC, crv=P-256, x, y).
  public_key_jwk  JSONB NOT NULL,
  sign_count      BIGINT NOT NULL DEFAULT 0,
  nickname        TEXT
                  CHECK (nickname IS NULL OR char_length(nickname) <= 128),
  created_by      TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at    TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ,
  revoked_by      TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS break_glass_admin_webauthn_cred_uidx
  ON break_glass_admin_webauthn (credential_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS break_glass_admin_webauthn_principal_idx
  ON break_glass_admin_webauthn (principal_id)
  WHERE revoked_at IS NULL;

COMMENT ON TABLE break_glass_admin_webauthn IS
  'AIM-719 hardware-key (WebAuthn-compatible ES256) credentials for emergency admin.';

CREATE TABLE IF NOT EXISTS break_glass_admin_grants (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_email       TEXT NOT NULL
                        CHECK (principal_email <> '' AND char_length(principal_email) <= 320),
  -- dual_control | webauthn
  method                TEXT NOT NULL
                        CHECK (method IN ('dual_control', 'webauthn')),
  status                TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN (
                          'pending', 'approved', 'activated', 'revoked', 'expired', 'denied'
                        )),
  reason                TEXT NOT NULL
                        CHECK (char_length(reason) BETWEEN 1 AND 2000),
  ticket_ref            TEXT
                        CHECK (ticket_ref IS NULL OR char_length(ticket_ref) <= 256),
  requested_by          TEXT NOT NULL,
  requested_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Dual control: two distinct approver identities required.
  first_approver        TEXT,
  first_approved_at     TIMESTAMPTZ,
  second_approver       TEXT,
  second_approved_at    TIMESTAMPTZ,
  -- One-way hash of one-time activation token (returned only on second approve).
  activation_token_hash TEXT
                        CHECK (activation_token_hash IS NULL OR char_length(activation_token_hash) = 64),
  activated_at          TIMESTAMPTZ,
  activated_by          TEXT,
  expires_at            TIMESTAMPTZ,
  -- Session TTL once activated (minutes). Short by design.
  ttl_minutes           INT NOT NULL DEFAULT 60
                        CHECK (ttl_minutes BETWEEN 5 AND 480),
  revoked_by            TEXT,
  revoked_at            TIMESTAMPTZ,
  revoke_reason         TEXT
                        CHECK (revoke_reason IS NULL OR char_length(revoke_reason) <= 2000),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS break_glass_admin_grants_status_idx
  ON break_glass_admin_grants (status, expires_at);
CREATE INDEX IF NOT EXISTS break_glass_admin_grants_principal_idx
  ON break_glass_admin_grants (lower(principal_email), status);
CREATE INDEX IF NOT EXISTS break_glass_admin_grants_requested_idx
  ON break_glass_admin_grants (requested_at DESC);

COMMENT ON TABLE break_glass_admin_grants IS
  'AIM-719 emergency admin grants: dual-control approvals or WebAuthn activation.';

CREATE TABLE IF NOT EXISTS break_glass_admin_events (
  id          BIGSERIAL PRIMARY KEY,
  grant_id    UUID REFERENCES break_glass_admin_grants(id) ON DELETE SET NULL,
  event_type  TEXT NOT NULL
              CHECK (event_type IN (
                'principal_added', 'principal_disabled',
                'webauthn_registered', 'webauthn_revoked', 'webauthn_auth',
                'grant_requested', 'grant_approved', 'grant_activated',
                'grant_revoked', 'grant_expired', 'grant_denied', 'note'
              )),
  actor       TEXT NOT NULL,
  detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS break_glass_admin_events_grant_idx
  ON break_glass_admin_events (grant_id, created_at);
CREATE INDEX IF NOT EXISTS break_glass_admin_events_created_idx
  ON break_glass_admin_events (created_at DESC);
CREATE INDEX IF NOT EXISTS break_glass_admin_events_type_idx
  ON break_glass_admin_events (event_type, created_at DESC);

COMMENT ON TABLE break_glass_admin_events IS
  'AIM-719 append-only audit of emergency admin break-glass lifecycle.';
