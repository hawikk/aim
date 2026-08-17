-- 032_fleet_coverage_daily.sql — AIM-619: daily fleet coverage history.
--
-- Powers optional `trend` on GET /api/fleet (AIM-588 Fleet coverage chart).
-- devices only holds a live snapshot (last_heartbeat_at); fabricating a
-- multi-day series from that alone would lie. This table stores one real
-- daily rollup per UTC calendar day, written by the API scheduler (and
-- refreshed for "today" on fleet reads).
--
-- Columns match the AIM-588 fixture contract (FLEET.trend):
--   day, deployed, healthy, stale, dead, never_seen, coverageGaps, healthyPct
-- plus silent/dropping for parity with the live fleet summary.
--
-- Privacy: aggregate integers only — no hostnames, host_ids, tokens, or
-- event content.
--
-- Retention: the API purges rows older than FLEET_COVERAGE_HISTORY_DAYS
-- (default 365).

CREATE TABLE IF NOT EXISTS fleet_coverage_daily (
  day               DATE PRIMARY KEY,
  captured_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  deployed          INTEGER NOT NULL DEFAULT 0,
  healthy           INTEGER NOT NULL DEFAULT 0,
  stale             INTEGER NOT NULL DEFAULT 0,
  dead              INTEGER NOT NULL DEFAULT 0,
  never_seen        INTEGER NOT NULL DEFAULT 0,
  silent            INTEGER NOT NULL DEFAULT 0,
  coverage_gaps     INTEGER NOT NULL DEFAULT 0,
  dropping          INTEGER NOT NULL DEFAULT 0,
  -- healthy/deployed * 100, one decimal (e.g. 88.9); 0 when deployed = 0.
  healthy_pct       DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS fleet_coverage_daily_day_desc_idx
  ON fleet_coverage_daily (day DESC);
