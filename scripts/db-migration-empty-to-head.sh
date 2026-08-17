#!/usr/bin/env bash
# Prove "fresh install migrates": empty Postgres → all migrations → head.
#
# Uses the real migrator (services/ingest/src/migrate.ts::runMigrations), not a
# reimplementation. Spins a throwaway postgres container so no local DB is
# required.
#
# Usage: ./scripts/db-migration-empty-to-head.sh
# Env:   POSTGRES_IMAGE   (default: postgres:16-alpine)
#        MIGRATIONS_DIR   (default: services/ingest/migrations)
#
# Exits non-zero if any check FAILs. Requires docker + node (>=20).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-$ROOT/services/ingest/migrations}"
IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
CONTAINER="aim-empty-head-$$"
DB_USER="aim"
DB_NAME="aim"
DB_PASSWORD="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
HOST_PORT=""

FAILURES=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }
check() {
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (expected [$2], got [$3])"; fi
}

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mapfile -t FILES < <(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' -printf '%f\n' | sort)
TOTAL=${#FILES[@]}
if (( TOTAL < 1 )); then
  echo "FAIL: no migration files in ${MIGRATIONS_DIR}"
  exit 1
fi

# Multi-head guard for the numbered SQL sequence.
DUPES=$(printf '%s\n' "${FILES[@]}" | sed 's/_.*//' | sort | uniq -d)
if [[ -n "$DUPES" ]]; then
  echo "FAIL: duplicate migration number(s):"
  printf '%s\n' "$DUPES" | sed 's/^/  /'
  exit 1
fi

echo "== empty → head: ${TOTAL} migration(s) via real runMigrations =="

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
for _ in $(seq 1 60); do
  if docker exec -e PGPASSWORD="$DB_PASSWORD" "$CONTAINER" \
    pg_isready -U "$DB_USER" -d "$DB_NAME" -q; then
    ready=1
    break
  fi
  sleep 1
done
if (( ready != 1 )); then
  echo "FAIL: postgres never became ready in ${CONTAINER}"
  docker logs "$CONTAINER" 2>&1 | tail -40 || true
  exit 1
fi

HOST_PORT=$(docker port "$CONTAINER" 5432/tcp | head -1 | sed 's/.*://')
if [[ -z "$HOST_PORT" ]]; then
  echo "FAIL: could not resolve published host port for ${CONTAINER}"
  exit 1
fi
DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@127.0.0.1:${HOST_PORT}/${DB_NAME}"

# pg_isready can succeed a beat before the TCP listener is stable under
# concurrent soft-runner load (CI saw ECONNRESET / "Connection terminated
# unexpectedly" on the first migrator pass). Wait for a real query too.
tcp_ready=0
for _ in $(seq 1 30); do
  if docker exec -e PGPASSWORD="$DB_PASSWORD" "$CONTAINER" \
    psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt -c 'SELECT 1' >/dev/null 2>&1; then
    tcp_ready=1
    break
  fi
  sleep 1
done
if (( tcp_ready != 1 )); then
  echo "FAIL: postgres accepted pg_isready but not SELECT 1"
  docker logs "$CONTAINER" 2>&1 | tail -40 || true
  exit 1
fi

# Prefer compiled dist (matches the image runtime). Fall back to source via
# Node's experimental strip-types so a clean checkout without a prior build
# still proves the path.
# Extract the migrator's JSON result line from mixed stdout/stderr.
# Node 22 emits MODULE_TYPELESS_PACKAGE_JSON warnings on stderr; under
# 2>&1 capture those must not be fed to JSON.parse (CI failure mode).
json_line() {
  printf '%s\n' "$1" | grep -E '^\{"applied":' | tail -1
}

applied_count() {
  local line
  line=$(json_line "$1")
  if [[ -z "$line" ]]; then
    echo "FAIL: no {\"applied\":...} JSON line in migrator output" >&2
    printf '%s\n' "$1" | tail -30 >&2
    return 1
  fi
  node -e 'const j=JSON.parse(process.argv[1]); process.stdout.write(String(j.applied.length));' "$line"
}

run_migrator() {
  local label="$1"
  local out
  # Keep Node noise off stdout so the only printed line is our JSON.
  export NODE_NO_WARNINGS=1
  if [[ -f "$ROOT/services/ingest/dist/migrate.js" ]]; then
    out=$(
      cd "$ROOT/services/ingest" && \
      DATABASE_URL="$DATABASE_URL" MIGRATIONS_DIR="$MIGRATIONS_DIR" \
      node --no-warnings <<'JS'
const { Pool } = require("pg");
const { runMigrations } = require("./dist/migrate.js");
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  connectionTimeoutMillis: 10_000,
});
runMigrations(pool, process.env.MIGRATIONS_DIR)
  .then((applied) => {
    process.stdout.write(JSON.stringify({ applied }) + "\n");
    return pool.end();
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
JS
    )
  else
    out=$(
      cd "$ROOT/services/ingest" && \
      NODE_PATH="$ROOT/services/ingest/node_modules" \
      DATABASE_URL="$DATABASE_URL" MIGRATIONS_DIR="$MIGRATIONS_DIR" \
      node --no-warnings --experimental-strip-types --disable-warning=MODULE_TYPELESS_PACKAGE_JSON <<'JS'
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const require = createRequire(import.meta.url);
const { Pool } = require("pg");
const migrateUrl = pathToFileURL(join(process.cwd(), "src/migrate.ts")).href;
const { runMigrations } = await import(migrateUrl);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  connectionTimeoutMillis: 10_000,
});
try {
  const applied = await runMigrations(pool, process.env.MIGRATIONS_DIR);
  process.stdout.write(JSON.stringify({ applied }) + "\n");
} finally {
  await pool.end();
}
JS
    )
  fi
  echo "$out"
  json_line "$out" >/dev/null || {
    echo "FAIL: migrator ($label) did not return applied list"
    echo "$out"
    return 1
  }
}

# Transient docker-proxy resets on soft co-located runners — retry migrator.
run_migrator_retry() {
  local label="$1"
  local attempt out rc
  for attempt in 1 2 3; do
    set +e
    # Capture stdout only for JSON; still surface stderr on failure via tee path.
    out=$(run_migrator "$label" 2>/tmp/aim-migrator-$$.err)
    rc=$?
    set -e
    if (( rc == 0 )) && json_line "$out" >/dev/null; then
      printf '%s\n' "$(json_line "$out")"
      rm -f /tmp/aim-migrator-$$.err
      return 0
    fi
    echo "WARN: migrator ($label) attempt ${attempt}/3 failed (rc=${rc})"
    printf '%s\n' "$out" | tail -20
    tail -20 /tmp/aim-migrator-$$.err 2>/dev/null || true
    sleep $((attempt * 2))
  done
  echo "FAIL: migrator ($label) failed after 3 attempts"
  rm -f /tmp/aim-migrator-$$.err
  return 1
}

echo "-- first pass (empty DB)"
FIRST=$(run_migrator_retry first)
echo "   $FIRST"
FIRST_COUNT=$(applied_count "$FIRST")
check "first pass applied all migrations" "$TOTAL" "$FIRST_COUNT"

echo "-- second pass (idempotent: zero pending)"
SECOND=$(run_migrator_retry second)
echo "   $SECOND"
SECOND_COUNT=$(applied_count "$SECOND")
check "second pass applies nothing" "0" "$SECOND_COUNT"

psql_() {
  docker exec -e PGPASSWORD="$DB_PASSWORD" -i "$CONTAINER" \
    psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt "$@"
}

LEDGER=$(psql_ -c "SELECT count(*) FROM schema_migrations")
check "schema_migrations ledger count" "$TOTAL" "$LEDGER"

PENDING=$(comm -23 \
  <(printf '%s\n' "${FILES[@]}") \
  <(psql_ -c "SELECT id FROM schema_migrations ORDER BY id"))
check "no pending migrations vs filesystem" "" "$PENDING"

# Canonical objects a fresh install must expose (tables introduced across the
# full migration set; additive, so all should exist at head).
for t in events findings devices finding_deliveries repo_labels saved_views \
         compliance_snapshots retention_audit enroll_tokens finding_transitions; do
  got=$(psql_ -c "SELECT to_regclass('$t')")
  check "table $t exists" "$t" "$got"
done

echo "=="
if (( FAILURES > 0 )); then
  echo "RESULT: FAIL (${FAILURES} check(s) failed)"
  exit 1
fi
echo "RESULT: PASS — empty DB migrates to head via runMigrations"
