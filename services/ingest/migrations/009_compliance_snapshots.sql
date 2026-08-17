-- AIM-99: scheduled compliance posture snapshots.
--
-- Stores the full compliance report (same shape as /api/compliance/report
-- JSON) so posture history is queryable instead of point-in-time only.
-- Retention is enforced by the API snapshot store per the `retention:`
-- section of policies/compliance/framework-map.yaml (weekly vs on-demand).
CREATE TABLE IF NOT EXISTS compliance_snapshots (
  id              BIGSERIAL PRIMARY KEY,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind            TEXT NOT NULL CHECK (kind IN ('weekly', 'on_demand')),
  period_from     TIMESTAMPTZ NOT NULL,
  period_to       TIMESTAMPTZ NOT NULL,
  -- Full report JSON (frameworks, coverage, audit-chain verdict, hashes).
  report          JSONB NOT NULL,
  -- sha256 over the canonical report payload — same construction as the
  -- export bundle hash, so snapshots and exports share one verifier.
  bundle_hash     TEXT NOT NULL,
  audit_chain_ok  BOOLEAN,
  findings_total  INTEGER NOT NULL DEFAULT 0,
  findings_open   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS compliance_snapshots_created_idx
  ON compliance_snapshots (created_at DESC);
