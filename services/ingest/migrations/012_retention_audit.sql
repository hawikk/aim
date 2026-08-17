-- 012_retention_audit.sql — retention enforcement audit trail.
--
-- Every purge run (Postgres event/finding purge, see src/retention.ts) writes
-- one metadata-only row here per data class it swept. This is the "deletions
-- must be explainable" record: what class, what window, the exact cutoff, and
-- how many rows went. It carries NO event content and NO pseudonyms — only the
-- shape of the deletion.
--
-- Retention of this table is itself governed by the `audit` data class
-- (default 730d, and audit >= findings >= events is enforced in config), so
-- the purge sweeps its own old records too. Because a run computes its cutoff
-- at start and only deletes rows strictly older than `now - audit_window`, a
-- run can never delete the audit records it (or any recent run) just wrote —
-- regression-tested in test/retention.test.ts.
--
-- Blast radius: this table has no foreign keys pointing at it and is written
-- append-only by the purger, so a buggy purge cannot cascade into the events
-- or findings tables through it.

CREATE TABLE IF NOT EXISTS retention_audit (
  id            BIGSERIAL PRIMARY KEY,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- correlates the per-class rows of a single purge run
  run_id        UUID NOT NULL,
  -- 'events' | 'findings' | 'audit' — the data class swept
  data_class    TEXT NOT NULL,
  -- the configured retention window for that class, in days
  window_days   INTEGER NOT NULL,
  -- rows strictly older than this instant were purged (boundary rule:
  -- age == window is KEPT; see src/retention.ts)
  cutoff_ts     TIMESTAMPTZ NOT NULL,
  -- rows actually deleted, or (when dry_run) rows that WOULD be deleted
  rows_deleted  BIGINT NOT NULL,
  -- true = reported only, nothing deleted
  dry_run       BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_retention_audit_created ON retention_audit (created_at);
CREATE INDEX IF NOT EXISTS idx_retention_audit_run ON retention_audit (run_id);
