-- 019_enroll_token_bound_email.sql — AIM-455: bind enrollment to a directory human.
--
-- The enroll flow previously only minted a device_id + device_token. Identity
-- resolution needs a row in identity-sync.device_mappings, and that table had a
-- write path only in tests. Minting an enrollment token *for* a known engineer
-- (bound_email) is the pilot-friendly join: when POST /v1/enroll redeems the
-- token, ingest registers device_id -> bound_email with identity-sync so the
-- next event batch resolves.
--
-- Privacy: bound_email lives only in enroll_tokens (admin surface) and is
-- forwarded once into identity-sync's device_mappings (also off the event
-- store). Events continue to carry user_pseudonym only.

ALTER TABLE enroll_tokens
  ADD COLUMN IF NOT EXISTS bound_email TEXT;

COMMENT ON COLUMN enroll_tokens.bound_email IS
  'Optional directory primary_email this token attributes devices to (AIM-455). NULL = unbound fleet/bootstrap token.';
