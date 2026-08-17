-- access review / attestation campaigns for AIM roles.
--
-- Snapshots of who held admin/analyst/auditor/viewer (+ reveal grant) at
-- review time, plus the attestation seal (who signed, when, statement).
-- Process-local store is the request-path source of truth; this table is
-- write-through so reviews survive process restart (same pattern as
-- session_revocations / scim_*).

CREATE TABLE IF NOT EXISTS access_review_campaigns (
  id              TEXT PRIMARY KEY,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  status          TEXT NOT NULL CHECK (status IN ('open', 'attested', 'cancelled')),
  period_label    TEXT,
  notes           TEXT,
  created_by      TEXT NOT NULL,
  roster          JSONB NOT NULL,
  principal_count INTEGER NOT NULL DEFAULT 0,
  attested_at     TIMESTAMPTZ,
  attested_by     TEXT,
  statement       TEXT,
  roster_hash     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS access_review_campaigns_created_idx
  ON access_review_campaigns (created_at DESC);

CREATE INDEX IF NOT EXISTS access_review_campaigns_status_idx
  ON access_review_campaigns (status);
