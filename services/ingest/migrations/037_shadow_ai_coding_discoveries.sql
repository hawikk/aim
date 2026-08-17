-- 037_shadow_ai_coding_discoveries.sql — unknown_ai_coding_tool findings.
--
-- Materialized discovery rows for uncatalogued AI coding tools (binary/domain/
-- process heuristics). Analyst disposition is on the platform findings table;
-- this table is the shadow-ai inventory for the discovery queue.

CREATE TABLE IF NOT EXISTS shadow_ai_coding_discoveries (
  finding_id        TEXT PRIMARY KEY,
  rule_id           TEXT NOT NULL DEFAULT 'unknown_ai_coding_tool',
  severity          TEXT NOT NULL,
  title             TEXT NOT NULL,
  signal_source     TEXT NOT NULL CHECK (signal_source IN ('idp_oauth', 'proxy_domain', 'process')),
  signal_value      TEXT NOT NULL,
  tool_slug         TEXT NOT NULL,
  matched_patterns  JSONB NOT NULL DEFAULT '[]',
  strength          TEXT NOT NULL CHECK (strength IN ('strong', 'weak')),
  identity_count    INTEGER,
  host_count        INTEGER,
  event_count       INTEGER,
  first_seen        TIMESTAMPTZ,
  last_seen         TIMESTAMPTZ,
  computed_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_shadow_ai_coding_discoveries_slug
  ON shadow_ai_coding_discoveries (tool_slug);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_coding_discoveries_source
  ON shadow_ai_coding_discoveries (signal_source);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_coding_discoveries_rule
  ON shadow_ai_coding_discoveries (rule_id);
