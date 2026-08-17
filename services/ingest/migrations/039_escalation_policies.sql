-- 039_escalation_policies.sql — multi-stage escalation routing +
-- PagerDuty as a first-class finding_deliveries destination.
--
-- Wave-1 destinations (webhook / Sentinel / Google Chat / Slack / SIEM) fan
-- out simultaneously. Escalation policies add *ordered stages with timers*
-- so a finding can page Slack first, then PagerDuty if still open (status
-- still 'new') after N seconds — on-call style routing without re-paging
-- once an analyst has acknowledged or resolved the finding.
--
-- 1. Widen finding_deliveries.destination for 'pagerduty' (Events API v2).
-- 2. finding_escalation_state tracks which stage has fired for each finding
--    and when the next stage is due. Active rows with next_stage_at <= now()
--    are advanced by the guardrail evaluate-db sweep (escalation.py).
--
-- Retention: escalation rows are operational state for open findings; they
-- age out with the findings data class (default 90d). Until a retention
-- sweep covers this table:
--   DELETE FROM finding_escalation_state
--    WHERE enrolled_at < now() - interval '90 days';

ALTER TABLE finding_deliveries DROP CONSTRAINT IF EXISTS finding_deliveries_destination_check;
ALTER TABLE finding_deliveries
  ADD CONSTRAINT finding_deliveries_destination_check
  CHECK (destination IN (
    'webhook',
    'sentinel',
    'bus',
    'splunk_hec',
    'syslog_cef',
    'google_chat',
    'slack',
    'email',
    'pagerduty'
  ));

CREATE TABLE IF NOT EXISTS finding_escalation_state (
  finding_id      UUID PRIMARY KEY REFERENCES findings (finding_id),
  -- Policy id from settings.alerts.escalation_policies[].id
  policy_id       TEXT NOT NULL,
  -- Index of the last stage that has already been delivered (0-based).
  stage_index     INT  NOT NULL DEFAULT 0
                  CHECK (stage_index >= 0),
  -- When the next stage should fire. NULL when exhausted or stopped.
  next_stage_at   TIMESTAMPTZ,
  -- active: waiting on timers / still open
  -- exhausted: every stage has fired
  -- stopped: finding left status='new' (acked/resolved/fp) before later stages
  status          TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'exhausted', 'stopped')),
  stopped_reason  TEXT,
  enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Due-queue for the evaluate-db sweep: only active rows with a timer.
CREATE INDEX IF NOT EXISTS idx_finding_escalation_due
  ON finding_escalation_state (next_stage_at)
  WHERE status = 'active' AND next_stage_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_finding_escalation_policy
  ON finding_escalation_state (policy_id, status);
