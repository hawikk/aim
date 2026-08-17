-- 034_shadow_ai_ops.sql
--   continuous catalogue ops (discovery queue) + disposition closed loop.
--
--   shadow_ai_discovery_queue — uncatalogued IdP apps waiting for catalogue PR
--   shadow_ai_dispositions    — analyst allow / watch / propose_enforce / known_non_ai
--
-- Privacy: app names + client ids + pseudonym counts only. No emails, no content.
-- Dispositions are append-only (same contract as finding_transitions):
-- a "correction" is a new INSERT, never UPDATE/DELETE.

CREATE TABLE IF NOT EXISTS shadow_ai_discovery_queue (
  queue_id          TEXT PRIMARY KEY,
  app_name          TEXT NOT NULL,
  -- Empty string when the IdP grant had no client_id — keeps UNIQUE stable
  -- across SQLite and Postgres (NULL is not equal to NULL in UNIQUE).
  client_id         TEXT NOT NULL DEFAULT '',
  idp_sources       JSONB NOT NULL DEFAULT '[]',
  identity_count    INTEGER NOT NULL DEFAULT 0,
  grant_count       INTEGER NOT NULL DEFAULT 0,
  first_seen        TIMESTAMPTZ NOT NULL,
  last_seen         TIMESTAMPTZ NOT NULL,
  proposed_tool_id  TEXT,
  proposed_entry    JSONB,
  status            TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'proposed', 'catalogued', 'dismissed', 'known_non_ai')),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_discovery_app_client UNIQUE (app_name, client_id)
);

CREATE INDEX IF NOT EXISTS idx_shadow_ai_discovery_status
  ON shadow_ai_discovery_queue (status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_discovery_app
  ON shadow_ai_discovery_queue (app_name);

CREATE TABLE IF NOT EXISTS shadow_ai_dispositions (
  disposition_id  TEXT PRIMARY KEY,
  target_kind     TEXT NOT NULL CHECK (target_kind IN ('finding', 'app', 'tool')),
  target_key      TEXT NOT NULL,
  action          TEXT NOT NULL
                  CHECK (action IN ('allow', 'watch', 'propose_enforce', 'known_non_ai', 'catalogue')),
  reason          TEXT NOT NULL,
  actor           TEXT NOT NULL,
  finding_id      TEXT,
  app_name        TEXT,
  tool_id         TEXT,
  client_id       TEXT,
  metadata        JSONB NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_shadow_ai_dispositions_target
  ON shadow_ai_dispositions (target_kind, target_key, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_dispositions_action
  ON shadow_ai_dispositions (action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_dispositions_app
  ON shadow_ai_dispositions (app_name);

-- Append-only guard (mirrors 020_finding_transitions_append_only.sql).
CREATE OR REPLACE FUNCTION shadow_ai_dispositions_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'shadow_ai_dispositions is append-only: % is not allowed', TG_OP
    USING ERRCODE = '42501';
END;
$$;

DROP TRIGGER IF EXISTS trg_shadow_ai_dispositions_append_only ON shadow_ai_dispositions;
CREATE TRIGGER trg_shadow_ai_dispositions_append_only
  BEFORE UPDATE OR DELETE ON shadow_ai_dispositions
  FOR EACH ROW
  EXECUTE FUNCTION shadow_ai_dispositions_reject_mutation();

REVOKE UPDATE, DELETE ON shadow_ai_dispositions FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aim_app') THEN
    REVOKE UPDATE, DELETE ON shadow_ai_dispositions FROM aim_app;
    GRANT SELECT, INSERT ON shadow_ai_dispositions TO aim_app;
  END IF;
END
$$;
