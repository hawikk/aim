-- 015_principal_kind.sql — AIM-149: label machine attribution.
--
-- CEO/Security decision on the identity-source ADR: agent and CI hosts may be
-- attributed to their operator when one is known, and to a service principal
-- when one is not. That makes a second column necessary. Without it, an agent
-- host mapped to its operator is byte-for-byte indistinguishable from that
-- engineer typing into Claude Code on their own laptop — the per-engineer
-- views would silently charge autonomous machine activity to a named person.
--
--   'human'   resolved to a directory user via device/os_user/heuristic
--   'service' resolved via service_identities — a declared non-human host,
--             whether the pseudonym is the operator's or the service's own
--   NULL      unresolved, or ingested before this migration
--
-- Derived at resolution time from data we already hold. No new endpoint
-- telemetry, no new personal data.

ALTER TABLE events ADD COLUMN IF NOT EXISTS principal_kind TEXT;

-- Partial index: 'service' rows are the small side and the one dashboards
-- filter on ("exclude machine activity from per-engineer views").
CREATE INDEX IF NOT EXISTS idx_events_principal_kind
  ON events (principal_kind, received_at DESC)
  WHERE principal_kind IS NOT NULL;
