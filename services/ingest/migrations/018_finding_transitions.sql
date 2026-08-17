-- 018_finding_transitions.sql — AIM-223: append-only disposition transition
-- log for security findings (the "security events" of the AIM-94 triage
-- inbox).
--
-- Closes the auditability gap found in the AIM-223 delta audit: findings
-- carry only the LATEST disposition (status/triage_note/triaged_by/
-- triaged_at are UPDATEd in place, migration 003), so "who moved this, from
-- what, when, and why" was unanswerable from the database — it survived only
-- in the JSONL audit trail (AIM-27), which is not queryable per finding.
--
-- Lifecycle vocabulary is unchanged: new / acknowledged / resolved /
-- false_positive, a superset of the reference Open / Under Review / Resolved
-- lifecycle (new = Open, acknowledged = Under Review, resolved +
-- false_positive = Resolved with an explicit false-positive category). The
-- existing vocabulary is wired into saved views, CSV export, and filters;
-- renaming would churn all three for zero audit gain.
--
-- Append-only contract: the API only ever INSERTs here (routes/findings.js);
-- nothing UPDATEs or DELETEs. A transition that needs "correcting" is a new
-- transition, never an edit — same rule as the audit trail itself.
--
-- NOT backfilled: pre-migration triage actions were never recorded per
-- transition, and synthesizing rows for them would fabricate actor history.
-- The JSONL audit trail (AIM-27) remains the retroactive record for those.
--
-- Retention: transition rows are disposition metadata (actor + reason, no
-- finding content beyond the join key) and are purged with the findings data
-- class (default 90d) — a transition log that outlives the finding it
-- describes has no operational value. Until a retention sweep covers this
-- table the bound is enforced manually:
--   DELETE FROM finding_transitions WHERE created_at < now() - interval '90 days';

CREATE TABLE IF NOT EXISTS finding_transitions (
  -- Monotonic id gives a total order even for rows sharing a created_at
  -- (a bulk triage inserts its rows in one statement).
  transition_id BIGSERIAL PRIMARY KEY,
  finding_id    UUID NOT NULL REFERENCES findings (finding_id),
  -- Previous status. NOT NULL: every finding starts at 'new' (migration 003
  -- DEFAULT), so the source of a transition is always knowable.
  from_status   TEXT NOT NULL
                CHECK (from_status IN ('new', 'acknowledged', 'resolved', 'false_positive')),
  to_status     TEXT NOT NULL
                CHECK (to_status IN ('new', 'acknowledged', 'resolved', 'false_positive')),
  -- Session identity (email) of who moved it, mirroring findings.triaged_by
  -- and the audit-trail actor. Required: a disposition without an actor is
  -- the failure mode this table exists to close.
  actor         TEXT NOT NULL,
  -- Free-text reason. NULL except where the lifecycle demands one: the API
  -- rejects a transition to 'resolved' without a non-empty reason (AIM-223
  -- acceptance criterion), so resolved rows always carry one.
  reason        TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The history read path: all transitions for one finding, chronological.
CREATE INDEX IF NOT EXISTS idx_finding_transitions_finding
  ON finding_transitions (finding_id, created_at, transition_id);
