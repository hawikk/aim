#!/usr/bin/env bash
# Prove backup → restore into a clean environment preserves row counts and a
# sample of audit/finding records (AIM-291 AC3).
#
# What this exercises (compose-shaped, no live stack required):
#   1. Empty Postgres + all SQL migrations (fresh install)
#   2. Seed representative events / findings / retention_audit rows
#   3. pg_dump (custom format) + filesystem "object store" mirror of raw/
#   4. Tear down source DB; restore dump into a brand-new empty Postgres
#   5. Restore object-store mirror into a clean dir
#   6. Compare counts + sample audit row hashes
#
# Usage: ./scripts/backup-restore-proof.sh
# Env:   POSTGRES_IMAGE (default postgres:16-alpine)
#        MIGRATIONS_DIR (default services/ingest/migrations)
#        PROOF_DIR      (default mktemp under /tmp; cleaned on exit unless
#                        KEEP_PROOF_DIR=1)
#
# Requires: docker. Exits non-zero on any FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-$ROOT/services/ingest/migrations}"
IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
SRC="aim-br-src-$$"
DST="aim-br-dst-$$"
DB_USER="aim"
DB_NAME="aim"
DB_PASSWORD="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"

if [[ -n "${PROOF_DIR:-}" ]]; then
  mkdir -p "$PROOF_DIR"
else
  PROOF_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aim-backup-restore.XXXXXX")"
fi
DUMP="$PROOF_DIR/aim-pg.dump"
OBJ_SRC="$PROOF_DIR/minio-src/aim-telemetry"
OBJ_DST="$PROOF_DIR/minio-dst/aim-telemetry"
mkdir -p "$OBJ_SRC/raw/batch-1" "$OBJ_DST"

FAILURES=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }
check() {
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (expected [$2], got [$3])"; fi
}

cleanup() {
  docker rm -f "$SRC" "$DST" >/dev/null 2>&1 || true
  if [[ "${KEEP_PROOF_DIR:-0}" != "1" ]]; then
    rm -rf "$PROOF_DIR"
  else
    echo "(kept proof dir: $PROOF_DIR)"
  fi
}
trap cleanup EXIT

start_pg() { # $1 = container name
  if ! docker run -d --name "$1" \
    -e POSTGRES_USER="$DB_USER" \
    -e POSTGRES_PASSWORD="$DB_PASSWORD" \
    -e POSTGRES_DB="$DB_NAME" \
    -p 127.0.0.1::5432 \
    "$IMAGE" >/dev/null; then
    echo "FAIL: could not start postgres container $1 (${IMAGE})"
    exit 1
  fi
  for _ in $(seq 1 90); do
    if docker exec -e PGPASSWORD="$DB_PASSWORD" "$1" \
      psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt -c 'SELECT 1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "FAIL: postgres $1 never accepted SELECT 1"
  docker logs "$1" 2>&1 | tail -40 || true
  exit 1
}

psql_c() { # $1 = container, rest = psql args
  local c="$1"; shift
  local attempt
  for attempt in 1 2 3 4 5; do
    if docker exec -e PGPASSWORD="$DB_PASSWORD" -i "$c" \
      psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt "$@"; then
      return 0
    fi
    sleep "$attempt"
  done
  return 1
}

apply_all_migrations() { # $1 = container
  local c="$1"
  psql_c "$c" -c "CREATE TABLE IF NOT EXISTS schema_migrations (
    id TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );"
  mapfile -t FILES < <(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' -printf '%f\n' | sort)
  for f in "${FILES[@]}"; do
    {
      echo "BEGIN;"
      cat "$MIGRATIONS_DIR/$f"
      printf "INSERT INTO schema_migrations (id) VALUES ('%s');\n" "$f"
      echo "COMMIT;"
    } | psql_c "$c" -f -
  done
  echo "   applied ${#FILES[@]} migrations"
}

echo "== backup/restore proof =="
echo "proof dir: $PROOF_DIR"

echo "-- source: empty → head → seed"
start_pg "$SRC"
apply_all_migrations "$SRC"

psql_c "$SRC" <<'SQL'
INSERT INTO events (event_id, ts, source, tool, session_id, host_ref,
                    user_ref, repo_ref, tokens_in, tokens_out,
                    cost_estimate_usd, match_flags, payload)
VALUES
  ('11111111-1111-1111-1111-111111111111', '2026-07-01T10:00:00Z',
   'collector', 'claude-code', 'sess-br-1', 'host-hmac-1', 'user-hmac-1',
   'repo-hmac-1', 100, 40, 0.01, '[]'::jsonb,
   '{"schema":"ai-usage-event/v1","proof":"aim-291"}'::jsonb),
  ('22222222-2222-2222-2222-222222222222', '2026-07-01T11:00:00Z',
   'collector', 'cursor', 'sess-br-2', 'host-hmac-2', NULL, NULL,
   NULL, NULL, NULL, '["unattributed"]'::jsonb,
   '{"schema":"ai-usage-event/v1","proof":"aim-291"}'::jsonb);

INSERT INTO findings (finding_id, ts, rule_id, severity, title, subject,
                      evidence, policy_hash, decision, event_id, status)
VALUES ('33333333-3333-3333-3333-333333333333', '2026-07-01T10:00:00Z',
        'restricted-repo-access', 'high', 'Access to restricted repo',
        '{"user_ref":"user-hmac-1"}'::jsonb,
        '{"event_ids":["11111111-1111-1111-1111-111111111111"]}'::jsonb,
        'policyhash-br', 'observe', '11111111-1111-1111-1111-111111111111',
        'acknowledged');

INSERT INTO retention_audit (run_id, data_class, window_days, cutoff_ts,
                             rows_deleted, dry_run)
VALUES ('44444444-4444-4444-4444-444444444444', 'events', 90,
        '2026-04-01T00:00:00Z', 12, false),
       ('55555555-5555-5555-5555-555555555555', 'findings', 365,
        '2025-07-01T00:00:00Z', 0, true);
SQL

# Sample object-store payload (raw batch archival shape).
echo '{"batch_id":"b1","events":2,"proof":"aim-291"}' > "$OBJ_SRC/raw/batch-1/events.json"
echo 'deadbeef' > "$OBJ_SRC/raw/batch-1/payload.bin"

# Snapshot expected state.
SRC_EVENTS=$(psql_c "$SRC" -c "SELECT count(*) FROM events")
SRC_FINDINGS=$(psql_c "$SRC" -c "SELECT count(*) FROM findings")
SRC_AUDIT=$(psql_c "$SRC" -c "SELECT count(*) FROM retention_audit")
SRC_AUDIT_HASH=$(psql_c "$SRC" -c "SELECT md5(string_agg(s, E'\n' ORDER BY s))
  FROM (SELECT (run_id::text || '|' || data_class || '|' || rows_deleted::text || '|' || dry_run::text) AS s
        FROM retention_audit) q")
SRC_FINDING_SAMPLE=$(psql_c "$SRC" -c "SELECT finding_id::text || '|' || rule_id || '|' || status
  FROM findings WHERE finding_id = '33333333-3333-3333-3333-333333333333'")
SRC_OBJ_HASH=$( (cd "$OBJ_SRC" && find . -type f | sort | xargs sha256sum | sha256sum | awk '{print $1}') )

echo "   source events=$SRC_EVENTS findings=$SRC_FINDINGS audit=$SRC_AUDIT"

echo "-- backup (pg_dump custom + object-store mirror)"
docker exec -e PGPASSWORD="$DB_PASSWORD" "$SRC" \
  pg_dump -U "$DB_USER" -d "$DB_NAME" --format=custom --no-owner \
  > "$DUMP"
# mc-compatible layout: mirror source tree into backup bundle.
cp -a "$OBJ_SRC/." "$PROOF_DIR/backup-minio/"
check "pg_dump produced non-empty dump" "1" \
  "$( [[ -s "$DUMP" ]] && echo 1 || echo 0 )"
check "object-store mirror has raw batch" "1" \
  "$( [[ -f "$PROOF_DIR/backup-minio/raw/batch-1/events.json" ]] && echo 1 || echo 0 )"

echo "-- destroy source, restore into clean destination"
docker rm -f "$SRC" >/dev/null
start_pg "$DST"
# Empty destination: only postgres bootstrap tables.
DST_PRE=$(psql_c "$DST" -c "SELECT count(*) FROM pg_tables WHERE schemaname='public'")
check "destination starts with empty public schema" "0" "$DST_PRE"

docker exec -i -e PGPASSWORD="$DB_PASSWORD" "$DST" \
  pg_restore -U "$DB_USER" -d "$DB_NAME" --no-owner --exit-on-error \
  < "$DUMP"

# Object store restore into clean dir.
rm -rf "$OBJ_DST"
mkdir -p "$OBJ_DST"
cp -a "$PROOF_DIR/backup-minio/." "$OBJ_DST/"

echo "-- verify restore"
DST_EVENTS=$(psql_c "$DST" -c "SELECT count(*) FROM events")
DST_FINDINGS=$(psql_c "$DST" -c "SELECT count(*) FROM findings")
DST_AUDIT=$(psql_c "$DST" -c "SELECT count(*) FROM retention_audit")
DST_AUDIT_HASH=$(psql_c "$DST" -c "SELECT md5(string_agg(s, E'\n' ORDER BY s))
  FROM (SELECT (run_id::text || '|' || data_class || '|' || rows_deleted::text || '|' || dry_run::text) AS s
        FROM retention_audit) q")
DST_FINDING_SAMPLE=$(psql_c "$DST" -c "SELECT finding_id::text || '|' || rule_id || '|' || status
  FROM findings WHERE finding_id = '33333333-3333-3333-3333-333333333333'")
DST_OBJ_HASH=$( (cd "$OBJ_DST" && find . -type f | sort | xargs sha256sum | sha256sum | awk '{print $1}') )
DST_LEDGER=$(psql_c "$DST" -c "SELECT count(*) FROM schema_migrations")
EXPECTED_LEDGER=$(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' | wc -l | tr -d ' ')

check "events row count" "$SRC_EVENTS" "$DST_EVENTS"
check "findings row count" "$SRC_FINDINGS" "$DST_FINDINGS"
check "retention_audit row count" "$SRC_AUDIT" "$DST_AUDIT"
check "retention_audit sample hash" "$SRC_AUDIT_HASH" "$DST_AUDIT_HASH"
check "finding sample identity" "$SRC_FINDING_SAMPLE" "$DST_FINDING_SAMPLE"
check "object-store content hash" "$SRC_OBJ_HASH" "$DST_OBJ_HASH"
check "schema_migrations ledger restored" "$EXPECTED_LEDGER" "$DST_LEDGER"

echo "=="
if (( FAILURES > 0 )); then
  echo "RESULT: FAIL (${FAILURES} check(s) failed)"
  exit 1
fi
echo "RESULT: PASS — backup restored into clean env with matching counts + audit sample"
echo "dump: $DUMP (removed on exit unless KEEP_PROOF_DIR=1)"
