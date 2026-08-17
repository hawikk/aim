-- 001_init.sql — initial events storage for the AI Monitoring ingest service.
--
-- Columns mirror the event schema v1
-- (packages/schema/schema/v1/ai-usage-event.schema.json), the metadata-only
-- contract collectors emit.
--
-- Privacy notes:
--   * `payload` holds the validated canonical event, which is metadata-only
--     by schema contract (no prompt/response text, no code content).
--   * host_ref / user_ref / repo_ref are salted-HMAC pseudonyms, never
--     cleartext identifiers (see schema field descriptions).
--   * `rejected_events` deliberately does NOT store the rejected payload:
--     an invalid event may contain arbitrary content, so we store only the
--     validation error, a SHA-256 hash of the payload, and its top-level
--     key names for audit correlation.

CREATE TABLE IF NOT EXISTS events (
  event_id            UUID PRIMARY KEY,
  ts                  TIMESTAMPTZ NOT NULL,
  received_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  source              TEXT NOT NULL,
  tool                TEXT NOT NULL,
  tool_raw            TEXT,
  tool_version        TEXT,
  provider            TEXT,
  model               TEXT,
  session_id          TEXT NOT NULL,
  tokens_in           INTEGER,
  tokens_out          INTEGER,
  cost_estimate_usd   NUMERIC(14, 6),
  host_ref            TEXT NOT NULL,
  user_ref            TEXT,
  repo_ref            TEXT,
  match_flags         JSONB NOT NULL,
  payload             JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_user_ref ON events (user_ref);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events (tool);
CREATE INDEX IF NOT EXISTS idx_events_session ON events (session_id);

CREATE TABLE IF NOT EXISTS rejected_events (
  id            BIGSERIAL PRIMARY KEY,
  received_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  batch_index   INTEGER NOT NULL,
  error         TEXT NOT NULL,
  payload_hash  TEXT NOT NULL,
  payload_keys  JSONB NOT NULL
);
