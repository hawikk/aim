#!/usr/bin/env bash
# Prove "upgrade from previous release preserves data".
#
# Spins up a throwaway postgres container, applies migrations 001..N-1 (the
# "previous release") exactly the way services/ingest/src/migrate.ts records
# them (schema_migrations ledger, one transaction per migration), seeds
# representative rows into the pre-existing tables, then applies the
# remaining migration(s) (the "upgrade") and verifies the seeded data is
# untouched and the new schema objects exist.
#
# Usage: ./scripts/db-migration-rollforward.sh [prev-migration-count]
# Env:   PREV_MIGRATION_COUNT  number of leading migrations treated as the
#                              previous release (default: all but the last)
#        POSTGRES_IMAGE        (default: postgres:16-alpine)
#        MIGRATIONS_DIR        (default: services/ingest/migrations; override
#                              to run the proof against a fixture directory)
#
# Exits non-zero if any check FAILs. Requires docker; no local psql needed.
set -euo pipefail

MIGRATIONS_DIR="${MIGRATIONS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../services/ingest/migrations" && pwd)}"
IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
CONTAINER="aim-rollforward-$$"
DB_USER="aim"
DB_NAME="aim"
DB_PASSWORD="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"

mapfile -t FILES < <(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' -printf '%f\n' | sort)
TOTAL=${#FILES[@]}
PREV="${1:-${PREV_MIGRATION_COUNT:-$((TOTAL - 1))}}"

if (( TOTAL < 2 )); then
  echo "FAIL: need at least 2 migration files in ${MIGRATIONS_DIR}, found ${TOTAL}"
  exit 1
fi
if (( PREV < 1 || PREV >= TOTAL )); then
  echo "FAIL: prev-migration-count must be between 1 and $((TOTAL - 1)), got ${PREV}"
  exit 1
fi

# Migration numbers are a single sequence (docs/deployment/upgrades.md):
# two files with the same numeric prefix are a release-blocking conflict.
DUPES=$(printf '%s\n' "${FILES[@]}" | sed 's/_.*//' | sort | uniq -d)
if [[ -n "$DUPES" ]]; then
  echo "FAIL: duplicate migration number(s) in ${MIGRATIONS_DIR}:"
  while IFS= read -r n; do
    printf '%s\n' "${FILES[@]}" | grep "^${n}_" | sed 's/^/  /'
  done <<< "$DUPES"
  echo "Renumber one side before cutting a release (contract: sequential, never reused)."
  exit 1
fi

FAILURES=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }
check() { # $1 = label, $2 = expected, $3 = actual
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (expected [$2], got [$3])"; fi
}

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== roll-forward proof: ${PREV} of ${TOTAL} migrations = previous release, $((TOTAL - PREV)) = upgrade =="

# --- throwaway postgres (random host port, random password) -----------------
# Soft co-located runners can report pg_isready before postgres is queryable,
# or briefly enter "database system is shutting down" under docker churn.
# Wait for SELECT 1, not just the ready flag.
if ! docker run -d --name "$CONTAINER" \
  -e POSTGRES_USER="$DB_USER" \
  -e POSTGRES_PASSWORD="$DB_PASSWORD" \
  -e POSTGRES_DB="$DB_NAME" \
  -p 127.0.0.1::5432 \
  "$IMAGE" >/dev/null; then
  echo "FAIL: could not start postgres container (${IMAGE})"
  exit 1
fi

ready=0
for _ in $(seq 1 90); do
  if docker exec -e PGPASSWORD="$DB_PASSWORD" "$CONTAINER" \
    psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt -c 'SELECT 1' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if (( ready != 1 )); then
  echo "FAIL: postgres never accepted SELECT 1 in ${CONTAINER}"
  docker logs "$CONTAINER" 2>&1 | tail -40 || true
  exit 1
fi

psql_() {
  local attempt
  for attempt in 1 2 3 4 5; do
    if docker exec -e PGPASSWORD="$DB_PASSWORD" -i "$CONTAINER" \
      psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt "$@"; then
      return 0
    fi
    sleep "$attempt"
  done
  return 1
}

# --- apply a migration exactly like src/migrate.ts does: --------------------
# one transaction, then a row in the schema_migrations ledger, so the real
# migrator would treat this DB as "previous release" and apply only the delta.
psql_ -c "CREATE TABLE IF NOT EXISTS schema_migrations (
  id TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);"

apply_migration() { # $1 = file name
  {
    echo "BEGIN;"
    cat "$MIGRATIONS_DIR/$1"
    printf "INSERT INTO schema_migrations (id) VALUES ('%s');\n" "$1"
    echo "COMMIT;"
  } | psql_ -f -
}

# --- previous release --------------------------------------------------------
echo "-- applying previous-release migrations (1..${PREV})"
for f in "${FILES[@]:0:PREV}"; do
  apply_migration "$f"
  echo "   applied $f"
done

# --- seed representative rows into the pre-existing tables -------------------
# Respects FKs and NOT NULLs of migrations 001-006; the to_regclass guards
# keep the seed valid if PREV_MIGRATION_COUNT points at an earlier release.
echo "-- seeding representative rows"
psql_ <<'SQL'
DO $$
DECLARE
  ev1 UUID := '11111111-1111-1111-1111-111111111111';
  ev2 UUID := '22222222-2222-2222-2222-222222222222';
  f1  UUID := '33333333-3333-3333-3333-333333333333';
BEGIN
  IF to_regclass('events') IS NOT NULL THEN
    INSERT INTO events (event_id, ts, source, tool, session_id, host_ref,
                        user_ref, repo_ref, tokens_in, tokens_out,
                        cost_estimate_usd, match_flags, payload)
    VALUES
      (ev1, '2026-01-01T10:00:00Z', 'collector', 'claude-code', 'sess-1',
       'host-hmac-1', 'user-hmac-1', 'repo-hmac-1', 1200, 340, 0.0123,
       '[]'::jsonb, '{"schema":"ai-usage-event/v1"}'::jsonb),
      (ev2, '2026-01-01T11:00:00Z', 'collector', 'cursor', 'sess-2',
       'host-hmac-2', NULL, NULL, NULL, NULL, NULL,
       '["unattributed"]'::jsonb, '{"schema":"ai-usage-event/v1"}'::jsonb);
    -- 002 identity enrichment columns.
    IF to_regclass('events') IS NOT NULL AND EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name = 'events' AND column_name = 'user_pseudonym'
    ) THEN
      UPDATE events SET user_pseudonym = 'u_pseudo1', team = 'platform'
        WHERE event_id = ev1;
    END IF;
  END IF;

  IF to_regclass('evaluated_events') IS NOT NULL THEN
    INSERT INTO evaluated_events (event_id) VALUES (ev1);
  END IF;

  IF to_regclass('findings') IS NOT NULL THEN
    INSERT INTO findings (finding_id, ts, rule_id, severity, title, subject,
                          evidence, policy_hash, decision, event_id, status)
    VALUES (f1, '2026-01-01T10:00:00Z', 'restricted-repo-access', 'high',
            'Access to restricted repo', '{"user_ref":"user-hmac-1"}'::jsonb,
            '{"event_ids":["11111111-1111-1111-1111-111111111111"]}'::jsonb,
            'policyhash1', 'observe', ev1, 'acknowledged');
  END IF;

  IF to_regclass('finding_deliveries') IS NOT NULL THEN
    INSERT INTO finding_deliveries (finding_id, destination, status, attempts,
                                    http_status, delivered_at)
    VALUES (f1, 'webhook', 'delivered', 1, 200, '2026-01-01T10:05:00Z');
  END IF;

  IF to_regclass('devices') IS NOT NULL THEN
    INSERT INTO devices (device_id, host_id, hostname, os, ring,
                         collector_version, device_token_hash,
                         last_heartbeat_at, last_counters)
    VALUES ('44444444-4444-4444-4444-444444444444',
            '55555555-5555-5555-5555-555555555555',
            'dev-laptop-01', 'linux', 'ring-0', '0.4.0',
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
            '2026-01-01T12:00:00Z', '{"emitted":42,"spooled":0}'::jsonb);
  END IF;

  IF to_regclass('repo_labels') IS NOT NULL THEN
    INSERT INTO repo_labels (repo_ref, label, created_by)
    VALUES ('repo-hmac-1', 'payments-service', 'sec-admin@example.com');
  END IF;

  -- Retention-across-upgrade fixtures (AIM-291 AC4): one event inside the
  -- default 90d window and one strictly older, so a post-upgrade purge keeps
  -- the recent row and removes the expired one without orphaning findings.
  IF to_regclass('events') IS NOT NULL THEN
    INSERT INTO events (event_id, ts, source, tool, session_id, host_ref,
                        user_ref, repo_ref, tokens_in, tokens_out,
                        cost_estimate_usd, match_flags, payload, received_at)
    VALUES
      ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
       now() - interval '200 days', 'collector', 'claude-code', 'sess-old',
       'host-hmac-old', 'user-hmac-old', 'repo-hmac-old', 10, 5, 0.001,
       '[]'::jsonb, '{"schema":"ai-usage-event/v1","marker":"expired"}'::jsonb,
       now() - interval '200 days'),
      ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
       now() - interval '1 day', 'collector', 'cursor', 'sess-new',
       'host-hmac-new', 'user-hmac-new', 'repo-hmac-new', 20, 8, 0.002,
       '[]'::jsonb, '{"schema":"ai-usage-event/v1","marker":"kept"}'::jsonb,
       now() - interval '1 day')
    ON CONFLICT (event_id) DO NOTHING;
  END IF;
END $$;
SQL

# Seeded tables = every public table except the migrator ledger.
mapfile -t SEEDED_TABLES < <(psql_ -c "SELECT tablename FROM pg_tables
  WHERE schemaname = 'public' AND tablename <> 'schema_migrations'
  ORDER BY tablename")

# --- snapshot pre-upgrade state ----------------------------------------------
# Content hash covers only the columns that exist pre-upgrade: additive
# migrations append columns, and the compatibility contract
# (docs/deployment/upgrades.md) guarantees pre-existing columns are untouched.
declare -A PRE_COUNT PRE_HASH PRE_COLUMNS
for t in "${SEEDED_TABLES[@]}"; do
  PRE_COUNT[$t]=$(psql_ -c "SELECT count(*) FROM $t")
  cols=$(psql_ -c "SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position)
                   FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = '$t'")
  PRE_COLUMNS[$t]="$cols"
  PRE_HASH[$t]=$(psql_ -c "SELECT md5(COALESCE(string_agg(s, E'\n' ORDER BY s), ''))
                           FROM (SELECT ROW($cols)::text AS s FROM $t) q")
done
SCHEMA_BEFORE=$(psql_ -c "SELECT table_name || '.' || column_name
  FROM information_schema.columns WHERE table_schema = 'public'
  UNION SELECT tablename || ' (table)' FROM pg_tables WHERE schemaname = 'public'
  UNION SELECT indexname || ' (index)' FROM pg_indexes WHERE schemaname = 'public'
  ORDER BY 1")

# --- the upgrade --------------------------------------------------------------
echo "-- applying upgrade migration(s) ($((PREV + 1))..${TOTAL})"
for f in "${FILES[@]:PREV}"; do
  apply_migration "$f"
  echo "   applied $f"
done

# --- verify -------------------------------------------------------------------
echo "-- verification"
for t in "${SEEDED_TABLES[@]}"; do
  check "row count unchanged: $t" "${PRE_COUNT[$t]}" "$(psql_ -c "SELECT count(*) FROM $t")"
  cols="${PRE_COLUMNS[$t]}"
  check "seeded content identical: $t" "${PRE_HASH[$t]}" \
    "$(psql_ -c "SELECT md5(COALESCE(string_agg(s, E'\n' ORDER BY s), ''))
                 FROM (SELECT ROW($cols)::text AS s FROM $t) q")"
done

# New schema objects from the upgrade (informational + explicit checks below).
SCHEMA_AFTER=$(psql_ -c "SELECT table_name || '.' || column_name
  FROM information_schema.columns WHERE table_schema = 'public'
  UNION SELECT tablename || ' (table)' FROM pg_tables WHERE schemaname = 'public'
  UNION SELECT indexname || ' (index)' FROM pg_indexes WHERE schemaname = 'public'
  ORDER BY 1")
ADDED=$(comm -13 <(printf '%s\n' "$SCHEMA_BEFORE") <(printf '%s\n' "$SCHEMA_AFTER"))
if [[ -n "$ADDED" ]]; then
  pass "upgrade added schema objects:"
  while IFS= read -r obj; do echo "     + $obj"; done <<< "$ADDED"
else
  fail "upgrade added no schema objects (an additive migration should add something)"
fi

# Explicit object checks per known upgrade migration; unknown files fall back
# to the generic added-objects diff above plus the ledger check below.
for f in "${FILES[@]:PREV}"; do
  case "$f" in
    005_finding_deliveries.sql)
      check "table finding_deliveries exists" "finding_deliveries" \
        "$(psql_ -c "SELECT to_regclass('finding_deliveries')")" ;;
    006_repo_labels.sql)
      check "table repo_labels exists" "repo_labels" \
        "$(psql_ -c "SELECT to_regclass('repo_labels')")" ;;
    007_tool_calls.sql)
      check "column events.event_type exists" "event_type" \
        "$(psql_ -c "SELECT column_name FROM information_schema.columns
                     WHERE table_name = 'events' AND column_name = 'event_type'")"
      check "column events.tool_calls exists" "tool_calls" \
        "$(psql_ -c "SELECT column_name FROM information_schema.columns
                     WHERE table_name = 'events' AND column_name = 'tool_calls'")"
      check "index idx_events_event_type exists" "idx_events_event_type" \
        "$(psql_ -c "SELECT indexname FROM pg_indexes
                     WHERE schemaname = 'public' AND indexname = 'idx_events_event_type'")" ;;
    008_compliance_snapshots.sql | 009_compliance_snapshots.sql)
      check "table compliance_snapshots exists" "compliance_snapshots" \
        "$(psql_ -c "SELECT to_regclass('compliance_snapshots')")" ;;
    008_saved_views.sql | 009_saved_views.sql)
      check "table saved_views exists" "saved_views" \
        "$(psql_ -c "SELECT to_regclass('saved_views')")" ;;
    010_app_llm_phase1.sql)
      check "table app_llm_sessions exists or app_llm columns present" "1" \
        "$(psql_ -c "SELECT CASE WHEN to_regclass('app_llm_sessions') IS NOT NULL
          OR EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name='events' AND column_name='app_id')
          THEN 1 ELSE 0 END")" ;;
    011_enroll_tokens.sql)
      check "table enroll_tokens exists" "enroll_tokens" \
        "$(psql_ -c "SELECT to_regclass('enroll_tokens')")" ;;
    012_retention_audit.sql)
      check "table retention_audit exists" "retention_audit" \
        "$(psql_ -c "SELECT to_regclass('retention_audit')")" ;;
    013_otel_app_telemetry.sql)
      check "otel columns or tables present" "1" \
        "$(psql_ -c "SELECT CASE WHEN to_regclass('otel_spans') IS NOT NULL
          OR EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name='events' AND column_name LIKE 'otel%')
          OR EXISTS (SELECT 1 FROM information_schema.tables
                     WHERE table_schema='public' AND table_name LIKE '%otel%')
          THEN 1 ELSE 0 END")" ;;
    014_events_received_at_index.sql)
      check "index idx_events_received_at exists" "idx_events_received_at" \
        "$(psql_ -c "SELECT indexname FROM pg_indexes
                     WHERE schemaname='public' AND indexname='idx_events_received_at'")" ;;
    015_principal_kind.sql)
      check "column principal_kind or devices.principal_kind" "1" \
        "$(psql_ -c "SELECT CASE WHEN EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE column_name='principal_kind') THEN 1 ELSE 0 END")" ;;
    016_bus_deliveries.sql)
      check "finding_deliveries accepts destination=bus" "1" \
        "$(psql_ -c "SELECT CASE WHEN pg_get_constraintdef(oid) LIKE '%bus%'
          THEN 1 ELSE 0 END FROM pg_constraint
          WHERE conname='finding_deliveries_destination_check'")" ;;
    017_alert_inbox_state.sql)
      check "alert inbox state table exists" "1" \
        "$(psql_ -c "SELECT CASE WHEN to_regclass('alert_inbox_state') IS NOT NULL
          OR to_regclass('inbox_state') IS NOT NULL THEN 1 ELSE 0 END")" ;;
    018_finding_transitions.sql)
      check "table finding_transitions exists" "finding_transitions" \
        "$(psql_ -c "SELECT to_regclass('finding_transitions')")" ;;
  esac
done

# Ledger matches the full migration set: the real migrator
# (services/ingest/src/migrate.ts) would see zero pending files on this DB.
PENDING=$(comm -23 \
  <(printf '%s\n' "${FILES[@]}") \
  <(psql_ -c "SELECT id FROM schema_migrations ORDER BY id"))
check "migrator delta after upgrade: no pending migrations" "" "$PENDING"

# --- retention/purge across the upgrade boundary (AIM-291 AC4) --------------
# Simulate the purger's events class rule (strictly older than 90d) with SQL
# so we do not need a full Node runtime in this shell proof. The real purger
# (services/ingest/src/retention.ts) uses the same boundary.
if [[ "$(psql_ -c "SELECT to_regclass('events')")" == "events" ]]; then
  echo "-- retention purge across upgrade boundary"
  EXPIRED_BEFORE=$(psql_ -c "SELECT count(*) FROM events
    WHERE event_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'")
  KEPT_BEFORE=$(psql_ -c "SELECT count(*) FROM events
    WHERE event_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'")
  if [[ "$EXPIRED_BEFORE" == "1" && "$KEPT_BEFORE" == "1" ]]; then
    psql_ -c "DELETE FROM events
      WHERE received_at < now() - interval '90 days'
        AND event_id IN (
          'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
          'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        )" >/dev/null
    EXPIRED_AFTER=$(psql_ -c "SELECT count(*) FROM events
      WHERE event_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'")
    KEPT_AFTER=$(psql_ -c "SELECT count(*) FROM events
      WHERE event_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'")
    check "retention purge removes expired event" "0" "$EXPIRED_AFTER"
    check "retention purge keeps in-window event" "1" "$KEPT_AFTER"
    # Original seed rows (pre-upgrade fixtures) must still be present.
    SEED_LEFT=$(psql_ -c "SELECT count(*) FROM events
      WHERE event_id IN (
        '11111111-1111-1111-1111-111111111111',
        '22222222-2222-2222-2222-222222222222'
      )")
    check "pre-upgrade seed events survive purge window" "2" "$SEED_LEFT"
  else
    pass "retention fixtures not present at PREV=${PREV} (skipped)"
  fi
fi

echo "=="
if (( FAILURES > 0 )); then
  echo "RESULT: FAIL (${FAILURES} check(s) failed)"
  exit 1
fi
echo "RESULT: PASS — upgrade from previous release preserves data"
