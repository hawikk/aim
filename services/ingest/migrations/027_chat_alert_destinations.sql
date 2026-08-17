-- 027_chat_alert_destinations.sql — AIM-485 / AIM-583: Google Chat + Slack
-- as first-class finding_deliveries destinations.
--
-- AIM-485 shipped GoogleChatNotifier (destination = 'google_chat') and
-- AIM-583 ships SlackNotifier (destination = 'slack') behind
-- ALERT_SLACK_ENABLED. Both reuse the same delivery accounting contract as
-- webhook / sentinel / bus / SIEM: one row per finding per destination.
--
-- The CHECK constraint on finding_deliveries.destination was last widened
-- by 024_siem_export for splunk_hec / syslog_cef. This migration adds the
-- two chat destinations so record_deliveries() can persist outcomes when
-- those notifiers fire. No other schema changes.
--
-- Retention: unchanged — delivery-accounting rows age out with their findings.

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
    'slack'
  ));
