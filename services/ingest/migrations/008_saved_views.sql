-- 008_saved_views.sql — AIM-94: per-user saved dashboard views.
--
-- Saved views are UI preferences owned by a single user: a named filter set
-- (status/severity/rule/time-range) for the findings console, persisted so the
-- dashboard can restore a triage workflow across sessions.
--
-- Privacy notes:
--   * Rows are per-user UI prefs only — owner_email plus filter criteria.
--     No telemetry content, no pseudonyms, no finding payloads are stored here.
--   * Access is owner-scoped at the API layer: a user can only read/write
--     their own views; the table is never cross-queried or aggregated.
--   * The filters point AT gated data APIs (/api/findings) but contain no
--     data themselves, so this table carries no privacy gate of its own.

CREATE TABLE IF NOT EXISTS saved_views (
  view_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_email TEXT NOT NULL,
  name        TEXT NOT NULL,
  filters     JSONB NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (owner_email, name)
);
