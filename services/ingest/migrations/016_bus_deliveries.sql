-- 016_bus_deliveries.sql — the alert bus as a delivery destination.
--
-- Two changes, both required by decision record D3.1 §4.5.
--
-- 1. `bus` joins the destination vocabulary. The guardrail publisher
--    (services/guardrail/src/guardrail/bus.py) records one row per finding
--    per destination exactly like the webhook and Sentinel notifiers, so
--    "did this finding reach the unified inbox?" is answerable from the same
--    table that already answers it for the SOC forwarders.
--
-- 2. The delivery row becomes *upgradable*. wrote these rows with
--    ON CONFLICT DO NOTHING because a finding was only ever forwarded on the
--    run that inserted it — one attempt, one outcome, done. The bus breaks
--    that assumption: D3.1 §4.5 requires a run-start sweeper that
--    re-publishes findings which committed but never reached the bus (a
--    redis-bus restart during a guardrail cycle is a routine event, not an
--    incident). Under DO NOTHING the retry would succeed while the audit row
--    still read 'failed' forever, which is worse than no row at all — it is a
--    security tool reporting non-delivery of an alert it did deliver.
--
--    That is a writer-side change — dbrunner.DELIVERY_INSERT now uses
--    ON CONFLICT (finding_id, destination) DO UPDATE ... WHERE status <>
--    'delivered', arbitrated by the UNIQUE (finding_id, destination) already
--    declared in 005 — so failed -> delivered is recorded while delivered
--    stays terminal: a later failure can never downgrade a delivery that
--    actually happened. It needs no schema change of its own and is noted
--    here because this is the migration that legalises 'bus', the
--    destination that requires it.
--
-- Retention: unchanged. These are delivery-accounting rows (finding
-- reference + transport metadata, no finding content) and age out with the
-- findings they reference.

ALTER TABLE finding_deliveries DROP CONSTRAINT IF EXISTS finding_deliveries_destination_check;
ALTER TABLE finding_deliveries
  ADD CONSTRAINT finding_deliveries_destination_check
  CHECK (destination IN ('webhook', 'sentinel', 'bus'));

-- 3. A third status: 'rejected' — the alert could not be built validly, so it
--    was never published and never will be. This is distinct from 'failed'
--    (the transport was down; retrying is the right move) and it has to
--    exist, because the sweeper's anti-join treats "no delivered row" as
--    "retry me". Without a terminal state a permanently-unpublishable finding
--    is re-mapped, re-rejected and re-logged on every run forever, and enough
--    of them crowd genuinely retryable findings out of the sweep window.
--    Terminal is a deliberate trade: after fixing a publisher mapping bug,
--    re-publishing the affected findings means deleting their 'rejected' rows
--    (DELETE FROM finding_deliveries WHERE destination='bus' AND
--    status='rejected'), which the next sweep then picks up.
ALTER TABLE finding_deliveries DROP CONSTRAINT IF EXISTS finding_deliveries_status_check;
ALTER TABLE finding_deliveries
  ADD CONSTRAINT finding_deliveries_status_check
  CHECK (status IN ('delivered', 'failed', 'rejected'));

-- Lets the sweeper find "committed but never published" in one indexed scan
-- instead of a sequential scan over every delivery row.
CREATE INDEX IF NOT EXISTS idx_finding_deliveries_dest_status
  ON finding_deliveries (destination, status);

-- The sweep's anti-join probes (finding_id, destination); the UNIQUE from 005
-- already covers that direction, so no extra index is needed for it.
