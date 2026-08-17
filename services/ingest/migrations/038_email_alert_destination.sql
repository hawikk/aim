-- 038_email_alert_destination.sql — AIM-582: Email as a first-class
-- finding_deliveries destination.
--
-- AIM-582 ships EmailNotifier (destination = 'email') for SOC mailbox
-- routes. Delivery accounting reuses the same contract as webhook /
-- sentinel / bus / SIEM / chat: one row per finding per destination.
--
-- The CHECK constraint on finding_deliveries.destination is re-stated with
-- the full allowed set so this is safe whether or not intermediate chat
-- migrations applied:
--   webhook, sentinel, bus, splunk_hec, syslog_cef, google_chat, slack, email
--
-- Numbered 036 — main owns 030–035 (shadow-ai discoveries through break-glass).

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
    'email'
  ));
