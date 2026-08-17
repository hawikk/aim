-- 010_app_llm_phase1.sql — app-LLM visibility phase 1 (proxy path).
--
-- Source-class attribution + network volume metadata for provider-API
-- traffic, carried on schema v1.4 events:
--   traffic_class — 'application' | 'employee' | 'unknown', classified at the
--                   proxy collector from src_ip BEFORE pseudonymization; only
--                   the label is stored, never the IP.
--   bytes_up/down — request/response volume (cost-proxy metering).
--   http_status   — status mix per provider/app. Code only, never a body.
--
-- Privacy notes:
--   * traffic_class is a 3-value enum, not an identifier; it cannot re-identify
--     a host beyond what host_ref already allows.
--   * Byte counts and status codes are flow metadata (same class as APM).

ALTER TABLE events ADD COLUMN IF NOT EXISTS traffic_class TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS bytes_up BIGINT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS bytes_down BIGINT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS http_status INTEGER;

-- App-LLM view: per-provider rollups sliced by source class over time ranges.
CREATE INDEX IF NOT EXISTS idx_events_traffic_class ON events (traffic_class)
  WHERE traffic_class IS NOT NULL;
