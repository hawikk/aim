-- 020_finding_transitions_append_only.sql — AIM-432 F2/F3: enforce
-- append-only on finding_transitions and wire it into findings retention.
--
-- F2 — Append-only was convention only (routes/findings.js is the sole
-- writer). This migration hardens the contract at the database:
--
--   1. A BEFORE UPDATE OR DELETE trigger rejects any mutation of existing
--      rows with a clear SQLSTATE/message. Triggers fire even for the table
--      owner (the compose `aim` role), where REVOKE is ineffective.
--   2. When a non-owner application role is present (AIM_APP_ROLE env is
--      not used at migration time; we REVOKE from PUBLIC and from the
--      common non-owner role name if it exists), UPDATE/DELETE are
--      revoked. INSERT and SELECT remain so triage and the history
--      endpoint keep working.
--
-- F3 — Retention: transition rows age out with the findings they describe.
-- services/ingest/src/retention.ts now lists finding_transitions as a
-- findings-class dependent (FK-safe cascade before findings DELETE). The
-- manual 90d DELETE comment in 018 is superseded by that sweep.
--
-- A transition that needs "correcting" remains a new INSERT, never an edit
-- — same rule as the AIM-27 audit trail.

CREATE OR REPLACE FUNCTION finding_transitions_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'finding_transitions is append-only: % is not allowed', TG_OP
    USING ERRCODE = '42501'; -- insufficient_privilege
END;
$$;

DROP TRIGGER IF EXISTS trg_finding_transitions_append_only ON finding_transitions;
CREATE TRIGGER trg_finding_transitions_append_only
  BEFORE UPDATE OR DELETE ON finding_transitions
  FOR EACH ROW
  EXECUTE FUNCTION finding_transitions_reject_mutation();

-- REVOKE from PUBLIC so any future non-owner app role cannot UPDATE/DELETE
-- even if someone GRANTs table privileges broadly later. Table owner (aim
-- in local compose) is unaffected by REVOKE; the trigger covers that path.
REVOKE UPDATE, DELETE ON finding_transitions FROM PUBLIC;

-- Optional: if an application role named aim_app exists, pin its grants.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aim_app') THEN
    REVOKE UPDATE, DELETE ON finding_transitions FROM aim_app;
    GRANT SELECT, INSERT ON finding_transitions TO aim_app;
    GRANT USAGE, SELECT ON SEQUENCE finding_transitions_transition_id_seq TO aim_app;
  END IF;
END
$$;
