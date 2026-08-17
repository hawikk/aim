-- 026_shadow_ai.sql — shadow AI discovery + SaaS/OAuth grants.
--
-- Tables owned by the shadow-ai discovery service (services/shadow-ai), read by
-- apps/api for the Shadow AI view and the analyst grant inventory:
--
--   shadow_ai_grants    — IdP OAuth grant sightings, one row per
--                         (pseudonym, IdP source, app). Grant-level metadata
--                         only: app name, client id, OAuth scope URIs,
--                         timestamps. NO content, NO URLs beyond domain level,
--                         NO emails (pseudonymized at sync time with the same
--                         HMAC scheme + key as identity-sync).
--   shadow_ai_tools     — materialized per-tool discovery inventory with risk
--                         scoring. Aggregate-only: no per-user fields.
-- shadow_ai_findings — unapproved_ai_saas_grant rows (account layer).
--                         Pseudonym + app + scopes; no emails.
--
-- Retention: revoked grants purged SHADOW_AI_REVOKED_RETENTION_DAYS (default 90)
-- after last sighting, enforced by the shadow-ai service on every sync.

CREATE TABLE IF NOT EXISTS shadow_ai_grants (
  id               BIGSERIAL PRIMARY KEY,
  user_pseudonym   TEXT NOT NULL,
  idp_source       TEXT NOT NULL,
  client_id        TEXT,
  app_name         TEXT NOT NULL,
  scopes           JSONB NOT NULL DEFAULT '[]',
  first_seen       TIMESTAMPTZ NOT NULL,
  last_seen        TIMESTAMPTZ NOT NULL,
  last_action      TEXT NOT NULL CHECK (last_action IN ('authorize', 'revoke')),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_grant_identity_app UNIQUE (user_pseudonym, idp_source, app_name)
);

CREATE INDEX IF NOT EXISTS idx_shadow_ai_grants_pseudonym ON shadow_ai_grants (user_pseudonym);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_grants_app ON shadow_ai_grants (app_name);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_grants_idp ON shadow_ai_grants (idp_source);

CREATE TABLE IF NOT EXISTS shadow_ai_tools (
  tool_id           TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  vendor            TEXT,
  catalogued        BOOLEAN NOT NULL,
  sanctioned        BOOLEAN,
  data_access_class TEXT,
  sources           JSONB NOT NULL DEFAULT '[]',
  attribution       TEXT NOT NULL CHECK (attribution IN ('attributed', 'unattributed', 'partial')),
  identity_count    INTEGER,
  scopes            JSONB NOT NULL DEFAULT '[]',
  scope_classes     JSONB NOT NULL DEFAULT '[]',
  first_seen        TIMESTAMPTZ,
  last_seen         TIMESTAMPTZ,
  risk_score        INTEGER NOT NULL,
  risk_band         TEXT NOT NULL CHECK (risk_band IN ('critical', 'high', 'medium', 'low')),
  risk_components   JSONB NOT NULL DEFAULT '[]',
  computed_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_shadow_ai_tools_risk ON shadow_ai_tools (risk_score DESC);

CREATE TABLE IF NOT EXISTS shadow_ai_findings (
  finding_id      TEXT PRIMARY KEY,
  rule_id         TEXT NOT NULL DEFAULT 'unapproved_ai_saas_grant',
  severity        TEXT NOT NULL,
  title           TEXT NOT NULL,
  user_pseudonym  TEXT NOT NULL,
  app_name        TEXT NOT NULL,
  tool_id         TEXT,
  client_id       TEXT,
  idp_source      TEXT NOT NULL,
  scopes          JSONB NOT NULL DEFAULT '[]',
  first_seen      TIMESTAMPTZ,
  last_seen       TIMESTAMPTZ,
  sanctioned      BOOLEAN,
  catalogued      BOOLEAN NOT NULL DEFAULT false,
  computed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_shadow_ai_findings_pseudonym ON shadow_ai_findings (user_pseudonym);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_findings_rule ON shadow_ai_findings (rule_id);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_findings_app ON shadow_ai_findings (app_name);
