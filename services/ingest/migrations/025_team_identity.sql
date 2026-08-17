-- 025_team_identity.sql — AIM-483: team display identity + membership overrides.
--
-- Attribution team keys (events.team) come from identity-sync at ingest time
-- and are effectively opaque bucket labels when device_mappings is empty.
-- These tables let a security-admin:
--   1. Attach a human-readable display name to a team key (rename without
--      rewriting historical events).
--   2. Assign/move a user pseudonym into a team (dashboard override; does NOT
--      rewrite event history or silently de-pseudonymize anyone).
--
-- Every write is also recorded in team_identity_audit (append-only here) and
-- mirrored into the hash-chained AUDIT_LOG by apps/api routes.
--
-- There is deliberately no FK to events.team: aliases may be set for keys not
-- yet seen in the range window, and event retention must not cascade into
-- governance data.

CREATE TABLE IF NOT EXISTS team_aliases (
  team_key     TEXT PRIMARY KEY,          -- attribution bucket key (e.g. Platform)
  display_name TEXT NOT NULL,             -- operator-chosen label
  updated_by   TEXT NOT NULL,             -- security-admin email who last set it
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS team_member_overrides (
  pseudonym    TEXT PRIMARY KEY,          -- user_pseudonym or user_ref from events
  team_key     TEXT NOT NULL,             -- destination team attribution key
  updated_by   TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_team_member_overrides_team
  ON team_member_overrides (team_key);

CREATE TABLE IF NOT EXISTS team_identity_audit (
  id           BIGSERIAL PRIMARY KEY,
  ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor        TEXT NOT NULL,
  action       TEXT NOT NULL,              -- team.rename | team.member.assign | team.member.clear
  team_key     TEXT,
  detail       JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_team_identity_audit_ts
  ON team_identity_audit (ts DESC);
