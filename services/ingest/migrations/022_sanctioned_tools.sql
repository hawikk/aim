-- 022_sanctioned_tools.sql — persisted sanctioned-tool allow-list.
--
-- Charter:
-- * The seed (claude_code, cursor, kilo_code) becomes rows in the
--     event-store DB rather than a hardcoded constant in aim-api.
--   * Admins mutate the list via the API (sanction / unsanction / note);
--     every mutation is audit-logged with actor identity from the verified
-- session (never a forgeable header).
--   * Consumers (dashboard, coverage, activity-score, governance report)
--     read the live list so coverage % and unapproved alerts recompute
--     without a process restart.
--
-- Empty table after seed would be a misconfiguration; the seed INSERT is
-- idempotent (ON CONFLICT DO NOTHING) so re-running is safe. The API falls
-- back to the same three defaults if the table is missing (pre-migration).

CREATE TABLE IF NOT EXISTS sanctioned_tools (
  tool         TEXT PRIMARY KEY
               CHECK (tool <> '' AND char_length(tool) <= 128),
  note         TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by   TEXT,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by   TEXT
);

COMMENT ON TABLE sanctioned_tools IS
  'Fleet sanctioned-tool allow-list. Seeded with defaults.';

-- locked seed. Do not remove these defaults from the migration
-- fresh installs must boot with the same three tools that the constant
-- shipped for the pilot.
INSERT INTO sanctioned_tools (tool, note, created_by, updated_by)
VALUES
  ('claude_code', 'Seed: Claude Code', 'system:seed', 'system:seed'),
  ('cursor', 'Seed: Cursor', 'system:seed', 'system:seed'),
  ('kilo_code', 'Seed: Kilo Code', 'system:seed', 'system:seed')
ON CONFLICT (tool) DO NOTHING;
