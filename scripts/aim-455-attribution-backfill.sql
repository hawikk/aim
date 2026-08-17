-- AIM-455: backfill event attribution where a binding now exists.
--
-- Why this is host_ref-scoped, not re-resolve-from-identity-sync:
--   Events intentionally do NOT store device_id / os_user / email (least-
--   privilege collection). The only durable endpoint key on the event row is
--   host_ref (HMAC of hostname). Full re-POST /resolve is therefore impossible
--   for historical rows: there is no join key left to feed the resolver.
--
-- What we CAN do safely:
--   When a host_ref already has a *unique, non-null* (user_pseudonym,
--   principal_kind, team) fingerprint on some of its events — meaning a live
--   resolver hit stamped that host after device_mappings / service_identities
--   were populated — copy that fingerprint onto the still-unattributed rows
--   for the same host_ref. Same host, same binding, same answer.
--
-- What we refuse:
--   Hosts with zero attributed events (no signal to propagate).
--   Hosts with conflicting attributed fingerprints (ambiguous; leave alone).
--   Inventing a human from user_ref / heuristic after the fact.
--
-- Run:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f scripts/aim-455-attribution-backfill.sql
-- Dry-run counts first (CTE preview), then UPDATE in one transaction.

BEGIN;

CREATE TEMP TABLE aim455_host_attribution ON COMMIT DROP AS
WITH attributed AS (
  SELECT
    host_ref,
    user_pseudonym,
    principal_kind,
    team,
    count(*) AS n
  FROM events
  WHERE user_pseudonym IS NOT NULL
    AND principal_kind IN ('human', 'service')
  GROUP BY 1, 2, 3, 4
),
unique_hosts AS (
  SELECT host_ref
  FROM attributed
  GROUP BY host_ref
  HAVING count(*) = 1
)
SELECT a.host_ref, a.user_pseudonym, a.principal_kind, a.team, a.n AS source_events
FROM attributed a
JOIN unique_hosts u USING (host_ref);

-- Preview: how many rows would change.
SELECT
  (SELECT count(*) FROM aim455_host_attribution) AS hosts_with_unique_attribution,
  (
    SELECT count(*)
    FROM events e
    JOIN aim455_host_attribution a USING (host_ref)
    WHERE e.user_pseudonym IS NULL
       OR e.principal_kind IS NULL
       OR e.principal_kind = 'unknown'
  ) AS events_to_stamp;

UPDATE events e
SET
  user_pseudonym = COALESCE(e.user_pseudonym, a.user_pseudonym),
  principal_kind = CASE
    WHEN e.principal_kind IS NULL OR e.principal_kind = 'unknown'
      THEN a.principal_kind
    ELSE e.principal_kind
  END,
  team = COALESCE(e.team, a.team)
FROM aim455_host_attribution a
WHERE e.host_ref = a.host_ref
  AND (
    e.user_pseudonym IS NULL
    OR e.principal_kind IS NULL
    OR e.principal_kind = 'unknown'
    OR e.team IS NULL
  );

-- Result summary.
SELECT
  count(*) AS total,
  count(user_pseudonym) AS with_pseudonym,
  count(*) FILTER (WHERE principal_kind = 'service') AS service_kind,
  count(*) FILTER (WHERE principal_kind = 'human') AS human_kind,
  count(*) FILTER (WHERE principal_kind IS NULL OR principal_kind = 'unknown') AS unknown_kind,
  round(
    100.0 * count(*) FILTER (
      WHERE user_pseudonym IS NOT NULL OR principal_kind = 'service'
    ) / NULLIF(count(*), 0),
    2
  ) AS pct_attributed
FROM events;

COMMIT;
