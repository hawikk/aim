-- 007_tool_calls.sql — AIM-86: tool_use event storage (schema v1.1).
--
-- Schema v1.1 adds the optional event_type discriminator ("usage" | "tool_use",
-- absent = "usage") and tool_calls[] aggregates describing agent tool
-- invocations (shell, file writes, network, MCP calls). Both are stored in
-- dedicated columns so dashboards can filter/aggregate without unpacking the
-- canonical payload.
--
-- Privacy notes:
--   * tool_calls is metadata-only by schema contract (packages/schema/schema/
--     v1/ai-usage-event.schema.json): tool name, action class, count, duration
--     — NEVER arguments, file paths, command lines, or tool output.
--     additionalProperties:false on entries means any attempt to attach
--     arguments fails ingest validation before it reaches this table.
--   * mcp_server names infrastructure (the collector's own MCP config id),
--     not user data; it is matched against the approved-server allowlist.

ALTER TABLE events ADD COLUMN IF NOT EXISTS event_type TEXT NOT NULL DEFAULT 'usage';
ALTER TABLE events ADD COLUMN IF NOT EXISTS tool_calls JSONB;

CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type);
