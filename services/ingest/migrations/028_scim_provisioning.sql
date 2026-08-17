-- 027_scim_provisioning.sql — AIM-713: SCIM 2.0 User/Group provisioning store.
--
-- Enterprise IdPs (Okta / Entra / Google) push user and group lifecycle into
-- AIM via /scim/v2/*. This migration is the durable directory those routes
-- write to. Auth (apps/api) hydrates an in-process cache and enforces
-- active=false on every SSO request so leavers lose access immediately —
-- not only at next OIDC login or session TTL.
--
-- Privacy: stores identity emails (required for SCIM userName) and group
-- display names only. No prompts, tokens, or content. SCIM bearer token is
-- configured via AIM_SCIM_BEARER_TOKEN (env secret), not this table.

CREATE TABLE IF NOT EXISTS scim_users (
  id            UUID PRIMARY KEY,
  user_name     TEXT NOT NULL,              -- lowercased email (SCIM userName)
  external_id   TEXT,                       -- IdP externalId (nullable)
  display_name  TEXT,
  active        BOOLEAN NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_scim_users_user_name UNIQUE (user_name)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_users_external_id
  ON scim_users (external_id)
  WHERE external_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scim_users_active
  ON scim_users (active);

CREATE TABLE IF NOT EXISTS scim_groups (
  id            UUID PRIMARY KEY,
  display_name  TEXT NOT NULL,
  external_id   TEXT,
  active        BOOLEAN NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_scim_groups_display_name UNIQUE (display_name)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_groups_external_id
  ON scim_groups (external_id)
  WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS scim_group_members (
  group_id  UUID NOT NULL REFERENCES scim_groups (id) ON DELETE CASCADE,
  user_id   UUID NOT NULL REFERENCES scim_users (id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_group_members_user
  ON scim_group_members (user_id);
