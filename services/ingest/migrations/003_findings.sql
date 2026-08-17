-- 003_findings.sql — AIM-32: guardrail findings storage + triage state.
--
-- Columns mirror the guardrail.finding/v1 schema emitted by the guardrail
-- engine (services/guardrail/src/guardrail/engine.py). Findings are produced
-- post-ingest by `guardrail evaluate-db`, which evaluates every stored event
-- exactly once (tracked in evaluated_events).
--
-- Privacy notes (docs/security/data-minimization.md):
--   * subject carries pseudonyms only (user_ref/host_ref HMACs).
--   * evidence carries detector names, event ids, and metadata-only context —
--     never matched content. Nothing here may store prompt/response text.
--
-- Triage columns are mutable (status workflow); the finding itself is
-- append-only. UNIQUE (rule_id, event_id) makes re-evaluation idempotent:
-- the same event firing the same rule never duplicates a finding.

CREATE TABLE IF NOT EXISTS findings (
  finding_id    UUID PRIMARY KEY,
  ts            TIMESTAMPTZ NOT NULL,           -- event ts (when it happened)
  detected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),  -- when the engine stored it
  rule_id       TEXT NOT NULL,
  severity      TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  title         TEXT NOT NULL,
  subject       JSONB NOT NULL,
  evidence      JSONB NOT NULL,
  policy_hash   TEXT NOT NULL,
  decision      TEXT NOT NULL,                  -- always 'observe' in v1
  event_id      UUID,                           -- primary triggering event (evidence.event_ids[0])
  status        TEXT NOT NULL DEFAULT 'new'
                CHECK (status IN ('new', 'acknowledged', 'resolved', 'false_positive')),
  triage_note   TEXT,
  triaged_by    TEXT,
  triaged_at    TIMESTAMPTZ,
  UNIQUE (rule_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings (rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings (ts);

-- Watermark for the post-ingest evaluator: which events have already been
-- through the engine. Threshold-rule windows are in-memory per run, so this
-- table (not a timestamp watermark) is the robust "exactly once" marker.
CREATE TABLE IF NOT EXISTS evaluated_events (
  event_id     UUID PRIMARY KEY REFERENCES events (event_id),
  evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
