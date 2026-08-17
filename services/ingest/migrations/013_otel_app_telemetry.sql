-- 009_otel_app_telemetry.sql — application-LLM telemetry columns (AIM-105).
--
-- Mirrors schema v1.3 additions (packages/schema/schema/v1/ai-usage-event.schema.json):
--   service_name  — OTel service.name of the instrumented first-party app
--                   (cleartext infrastructure name, like mcp_server; required
--                   for source='otel' events, null elsewhere).
--   duration_ms   — LLM call wall time from span start/end (latency signal).
--   status        — 'ok' | 'error' from span status; NEVER an error message.

ALTER TABLE events ADD COLUMN IF NOT EXISTS service_name TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS duration_ms INTEGER;
ALTER TABLE events ADD COLUMN IF NOT EXISTS status TEXT;

-- Per-app rollup queries filter on source + group by service_name.
CREATE INDEX IF NOT EXISTS idx_events_service_name ON events (service_name)
  WHERE service_name IS NOT NULL;
