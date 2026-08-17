-- 014_events_received_at_index.sql — AIM-149: index the server-accept time.
--
-- Two operational queries scan on received_at and had no index behind them:
--   * pipeline liveness  — max(received_at)                (polled every 60s)
--   * attribution health — count(*) over a trailing window (polled every 60s)
-- Without this index both degrade to a full scan of events, which is fine at
-- pilot volume and not fine at 700-engineer volume for an endpoint the whole
-- dashboard polls. max() over a btree is an index scan; the windowed count
-- becomes a range scan.
--
-- No new data is stored — this is purely an access-path change.

CREATE INDEX IF NOT EXISTS idx_events_received_at ON events (received_at);
