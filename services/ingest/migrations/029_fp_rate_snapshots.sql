-- 029_fp_rate_snapshots.sql — AIM-672: weekly live-pilot FP rate for
-- secret/PII detectors, stored so history is retained and the SLO can be
-- audited without re-deriving every week from a moving findings triage
-- state.
--
-- Metric (see docs/security/detector-fp-rate-slo.md):
--   session_fp_rate = distinct sessions with ≥1 false_positive finding
--                     on secret-pattern-in-prompt / pii-in-prompt
--                   / distinct sessions with ≥1 event
--   in a trailing period (default 7 days).
--
-- The API publishes the live rate on GET /api/security/fp-rate and writes
-- a weekly snapshot here. Breach alerts use the same security.alert/v1
-- bus as system-status / finding-SLA (finding_type
-- ai_usage.detector_fp_rate_breach).
--
-- Privacy: aggregates only — session counts, finding counts by rule/status,
-- no prompt/response text, no per-person rows.

CREATE TABLE IF NOT EXISTS fp_rate_snapshots (
  id              BIGSERIAL PRIMARY KEY,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind            TEXT NOT NULL CHECK (kind IN ('weekly', 'on_demand')),
  period_from     TIMESTAMPTZ NOT NULL,
  period_to       TIMESTAMPTZ NOT NULL,
  -- Full report JSON (metric, slo, by_rule, triage coverage, provenance).
  report          JSONB NOT NULL,
  -- Headline columns for list queries without unpacking JSONB.
  sessions        INTEGER NOT NULL DEFAULT 0,
  fp_sessions     INTEGER NOT NULL DEFAULT 0,
  session_fp_rate NUMERIC(10, 8) NOT NULL DEFAULT 0,
  slo_max_pct     NUMERIC(8, 4) NOT NULL DEFAULT 0.5,
  breached        BOOLEAN NOT NULL DEFAULT false,
  report_hash     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS fp_rate_snapshots_created_idx
  ON fp_rate_snapshots (created_at DESC);

CREATE INDEX IF NOT EXISTS fp_rate_snapshots_kind_created_idx
  ON fp_rate_snapshots (kind, created_at DESC);
