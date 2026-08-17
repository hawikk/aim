-- 002_identity_enrichment.sql — AIM-49: identity resolution enrichment.
--
-- The ingest pipeline resolves the batch's endpoint identity (device_id/os_user,
-- sent by the collector in the batch envelope) via the identity-sync service's
-- POST /resolve and stamps the returned pseudonym + team onto each stored event.
--
-- Privacy notes:
--   * user_pseudonym is "u_<hmac>" from identity-sync — never an email or name.
--   * Unresolved events keep user_pseudonym/team NULL and are still stored;
--     they feed the "unattributed usage" metric instead of being dropped.

ALTER TABLE events ADD COLUMN IF NOT EXISTS user_pseudonym TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS team TEXT;

CREATE INDEX IF NOT EXISTS idx_events_user_pseudonym ON events (user_pseudonym);
CREATE INDEX IF NOT EXISTS idx_events_team ON events (team);
