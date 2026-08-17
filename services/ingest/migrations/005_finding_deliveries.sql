-- 005_finding_deliveries.sql — AIM-76: alert delivery audit for findings.
--
-- The guardrail evaluator (services/guardrail dbrunner) forwards every newly
-- inserted finding to the configured alert destinations (generic webhook /
-- Microsoft Sentinel, see src/guardrail/notify.py) and records the outcome
-- here — one row per finding per destination. This is what makes "was the
-- SOC actually notified?" auditable without depending on the downstream
-- system being up:
--   status='delivered' — the receiver acknowledged (2xx) within the retry
--                        budget; delivered_at is set.
--   status='failed'    — retries exhausted or a non-retryable rejection;
--                        error carries the detail. The finding is NOT
--                        silently dropped: this row plus the
--                        guardrail.alert.error log line are the observability
--                        contract. Re-delivery is a manual/runbook action in
--                        v1 (rows are queryable by status).
--
-- UNIQUE (finding_id, destination) keeps re-runs idempotent: a finding is
-- only forwarded on the run that inserted it, and the outcome row is written
-- once.
--
-- Privacy: finding references and transport metadata only — the finding
-- payload itself stays in `findings`.

CREATE TABLE IF NOT EXISTS finding_deliveries (
  finding_id    UUID NOT NULL REFERENCES findings (finding_id),
  destination   TEXT NOT NULL CHECK (destination IN ('webhook', 'sentinel')),
  status        TEXT NOT NULL CHECK (status IN ('delivered', 'failed')),
  attempts      INT  NOT NULL DEFAULT 0,        -- delivery attempts made (1 + retries)
  http_status   INT,                            -- last HTTP status seen, if any
  error         TEXT,                           -- failure detail, if any
  delivered_at  TIMESTAMPTZ,                    -- set when status='delivered'
  recorded_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (finding_id, destination)
);

CREATE INDEX IF NOT EXISTS idx_finding_deliveries_status ON finding_deliveries (status);
CREATE INDEX IF NOT EXISTS idx_finding_deliveries_finding ON finding_deliveries (finding_id);
