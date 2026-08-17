-- 004_devices.sql — collector enrollment + heartbeat registry.
--
-- Backs POST /v1/enroll and POST /v1/heartbeat (contract:
-- docs/deployment/enrollment-and-heartbeat.md) and the coverage dashboard
-- query (deployed vs healthy vs fleet total).
--
-- Privacy notes:
--   * host_id is a random UUID generated on-device (state.host_id()), NOT a
--     hardware fingerprint — deliberate, for works-council/DPIA posture.
--   * hostname/os are low-sensitivity fleet metadata, needed to tell an
--     operator which physical machine a dead collector maps to.
--   * The per-device token is NEVER stored in cleartext: only its SHA-256
--     hash is persisted, mirroring the ingest bearer-token posture. A leaked
--     device token can be revoked (revoked_at) without touching the ring.
--   * Heartbeat counters are aggregate integers (events emitted/spooled),
--     never event content.

CREATE TABLE IF NOT EXISTS devices (
  device_id             UUID PRIMARY KEY,
  host_id               UUID NOT NULL UNIQUE,
  hostname              TEXT,
  os                    TEXT,
  ring                  TEXT,
  collector_version     TEXT,
  device_token_hash     TEXT NOT NULL,
  heartbeat_interval_sec INTEGER NOT NULL DEFAULT 300,
  enrolled_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_heartbeat_at     TIMESTAMPTZ,
  last_counters         JSONB,
  config_version        TIMESTAMPTZ,
  revoked_at            TIMESTAMPTZ
);

-- last-seen lookups drive the coverage/health rollup.
CREATE INDEX IF NOT EXISTS idx_devices_last_heartbeat ON devices (last_heartbeat_at);
CREATE INDEX IF NOT EXISTS idx_devices_ring ON devices (ring);
-- device-token auth looks up by hash on every heartbeat.
CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices (device_token_hash);
