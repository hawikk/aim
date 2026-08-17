-- 024_siem_export.sql — AIM-324: first-class SIEM export destinations and
-- dead-lettering on the finding_deliveries machinery.
--
-- Two changes to the delivery vocabulary:
--
-- 1. New destinations: 'splunk_hec' (Splunk HTTP Event Collector, OCSF
--    Detection Finding payload) and 'syslog_cef' (RFC 5424 syslog carrying the
--    CEF record — the fallback for SIEMs without an OCSF/HTTP intake). Both
--    reuse the exact accounting contract webhook/sentinel/bus already have:
--    one row per finding per destination, written by dbrunner.record_deliveries.
--
-- 2. A fourth status: 'dead' — the dead-letter state. AIM-76/AIM-158 gave us
--    'delivered' (terminal success), 'failed' (retryable), and 'rejected'
--    (terminal, unbuildable). The SIEM exporters are swept like the bus
--    (at-least-once, AIM-324), which forces the question the bus never had to
--    answer: when does a 'failed' row stop being retried? 'dead' is that
--    answer — a failed delivery whose attempts reached the destination's
--    sweep cap (dbrunner, per-notifier sweep_attempt_cap) is transitioned
--    failed -> dead by the run-start sweeper and never re-driven
--    automatically. Like 'rejected', it is terminal-but-reversible: after
--    fixing the outage's root cause, an operator replays with
--      DELETE FROM finding_deliveries
--      WHERE destination = '<dest>' AND status = 'dead';
--    and the next sweep picks the findings up again (the anti-join treats
--    "no row" as "retry me"). Dead-lettered rows are the visible lag signal:
--    guardrail.alert.lag reports per-destination pending/dead counts and the
--    age of the oldest pending finding on every run, and the same query backs
--    the poller's /lagz endpoint.
--
-- Why no schema columns: the sweep cap is enforced against the existing
-- `attempts` accumulator (016 made DELIVERY_INSERT add attempts across runs),
-- and redrive cadence is the guardrail run interval, so no next_attempt_at is
-- needed for v1. If per-destination backoff becomes necessary, add the column
-- in a later migration — nothing here forecloses it.
--
-- Retention: unchanged — delivery-accounting rows age out with their findings.

ALTER TABLE finding_deliveries DROP CONSTRAINT IF EXISTS finding_deliveries_destination_check;
ALTER TABLE finding_deliveries
  ADD CONSTRAINT finding_deliveries_destination_check
  CHECK (destination IN ('webhook', 'sentinel', 'bus', 'splunk_hec', 'syslog_cef'));

ALTER TABLE finding_deliveries DROP CONSTRAINT IF EXISTS finding_deliveries_status_check;
ALTER TABLE finding_deliveries
  ADD CONSTRAINT finding_deliveries_status_check
  CHECK (status IN ('delivered', 'failed', 'rejected', 'dead'));

-- The dead-letter transition and the lag query both filter on
-- (destination, status); idx_finding_deliveries_dest_status from 016 covers
-- both, so no new index is needed.
