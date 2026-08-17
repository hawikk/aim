-- 040_vendor_admin_daily.sql — AIM-1168: first-party vendor admin rollups.
--
-- Cursor Analytics and GitHub Copilot Metrics APIs are org-daily aggregates.
-- They are NOT written into `events` (that would invent users or collide with
-- endpoint/proxy rows). /api/tools and Overview read this sibling table.
--
-- Claude Code OTel (push) still lands in `events` as source='otel',
-- tool='claude_code'. Optional loc/commit extras from that exporter may also
-- upsert a claude_otel row here.
--
-- Privacy: extras JSONB is allowlist-filtered in application code before
-- insert. No emails, usernames, repo URLs, file paths, or prompt text.
-- Retention: same window as usage events (default 90d); the ingest purger
-- deletes rows whose day is strictly older than the events cutoff.

CREATE TABLE IF NOT EXISTS vendor_admin_daily (
  day DATE NOT NULL,
  feed TEXT NOT NULL,
  tool TEXT NOT NULL,
  tool_raw TEXT,
  active_users INTEGER NOT NULL DEFAULT 0,
  engaged_users INTEGER NOT NULL DEFAULT 0,
  sessions INTEGER NOT NULL DEFAULT 0,
  tokens_in BIGINT NOT NULL DEFAULT 0,
  tokens_out BIGINT NOT NULL DEFAULT 0,
  cost_usd NUMERIC NOT NULL DEFAULT 0,
  loc_suggested BIGINT NOT NULL DEFAULT 0,
  loc_accepted BIGINT NOT NULL DEFAULT 0,
  loc_committed_ai BIGINT NOT NULL DEFAULT 0,
  extras JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (day, feed)
);

CREATE INDEX IF NOT EXISTS vendor_admin_daily_feed_day_idx
  ON vendor_admin_daily (feed, day DESC);

CREATE TABLE IF NOT EXISTS vendor_admin_feeds (
  feed TEXT PRIMARY KEY,
  configured BOOLEAN NOT NULL DEFAULT false,
  last_attempt_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  last_error_class TEXT,
  last_day DATE,
  -- Operator-facing reason only. NEVER a token, Authorization header, or
  -- upstream response body (those may contain emails).
  detail TEXT
);
