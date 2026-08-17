#!/usr/bin/env bash
# — Automated pilot backup/restore drill with measured RTO / RPO.
#
# Runs a throwaway Postgres source → backup → destroy → clean restore → verify
# path (same recovery mechanics as scripts/backup-restore-proof.sh) while
# recording wall-clock phase timings and writing a durable drill log.
#
# What is measured
#   RTO  Wall-clock from "incident declared" (source destroyed) until all
#        integrity checks pass on the restored environment. This is the
#        technical restore time; operator detection/provisioning is outside
#        this script and is called out in the log.
#   RPO  Age of the backup at incident time: incident_epoch - backup_epoch.
#        For this continuous drill the lag is near-zero; the log also records
#        the pilot *scheduled* RPO target (nightly → 24h) for comparison.
#
# Exit codes
#   0  All integrity checks passed AND measured RTO ≤ PILOT_RTO_SECONDS
#   1  Integrity failure and/or RTO exceeded pilot target
#   2  Environment/setup failure (docker missing, migrations missing, …)
#
# Usage:
#   ./scripts/backup-restore-drill.sh
#   DRILL_LOG_DIR=docs/deployment/drills KEEP_PROOF_DIR=1 ./scripts/backup-restore-drill.sh
#
# Env:
#   POSTGRES_IMAGE        default postgres:16-alpine
#   MIGRATIONS_DIR        default services/ingest/migrations
#   PROOF_DIR             working dir for dump/mirror (default mktemp)
#   KEEP_PROOF_DIR=1      keep PROOF_DIR after exit
#   DRILL_LOG_DIR         where to write drill-*.{md,json} (default PROOF_DIR)
#   PILOT_RTO_SECONDS     RTO budget (default 28800 = 8 business hours)
#   PILOT_RPO_SECONDS     scheduled RPO target (default 86400 = 24h nightly)
#   DRILL_ID              optional id stamped into the log (default timestamp)
#   SIMULATE_BACKUP_LAG_S optional sleep after backup before incident (default 0)
#
# Requires: docker, bash, coreutils. Does not touch any live stack.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-$ROOT/services/ingest/migrations}"
IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
SRC="aim-drill-src-$$"
DST="aim-drill-dst-$$"
DB_USER="aim"
DB_NAME="aim"
DB_PASSWORD="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"

PILOT_RTO_SECONDS="${PILOT_RTO_SECONDS:-28800}"
PILOT_RPO_SECONDS="${PILOT_RPO_SECONDS:-86400}"
SIMULATE_BACKUP_LAG_S="${SIMULATE_BACKUP_LAG_S:-0}"
DRILL_STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DRILL_ID="${DRILL_ID:-aim598-$(date -u +%Y%m%dT%H%M%SZ)}"

if [[ -n "${PROOF_DIR:-}" ]]; then
  mkdir -p "$PROOF_DIR"
else
  PROOF_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aim-backup-restore-drill.XXXXXX")"
fi
DUMP="$PROOF_DIR/aim-pg.dump"
OBJ_SRC="$PROOF_DIR/minio-src/aim-telemetry"
OBJ_DST="$PROOF_DIR/minio-dst/aim-telemetry"
mkdir -p "$OBJ_SRC/raw/batch-1" "$OBJ_DST" "$PROOF_DIR/backup-minio"

DRILL_LOG_DIR="${DRILL_LOG_DIR:-$PROOF_DIR}"
mkdir -p "$DRILL_LOG_DIR"
LOG_MD="$DRILL_LOG_DIR/drill-${DRILL_ID}.md"
LOG_JSON="$DRILL_LOG_DIR/drill-${DRILL_ID}.json"

FAILURES=0
INTEGRITY_FAILURES=0
pass() { echo "PASS: $1"; }
fail() {
  echo "FAIL: $1"
  FAILURES=$((FAILURES + 1))
  INTEGRITY_FAILURES=$((INTEGRITY_FAILURES + 1))
}
check() {
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (expected [$2], got [$3])"; fi
}

# Phase timers (epoch seconds + human labels)
declare -A PHASE_START=()
declare -A PHASE_END=()
declare -A PHASE_SEC=()
phase_start() {
  local name="$1"
  PHASE_START["$name"]="$(date +%s)"
  echo "-- phase start: $name @ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
phase_end() {
  local name="$1"
  PHASE_END["$name"]="$(date +%s)"
  PHASE_SEC["$name"]=$(( PHASE_END["$name"] - PHASE_START["$name"] ))
  echo "-- phase end:   $name (${PHASE_SEC[$name]}s)"
}

cleanup() {
  docker rm -f "$SRC" "$DST" >/dev/null 2>&1 || true
  if [[ "${KEEP_PROOF_DIR:-0}" == "1" ]]; then
    echo "(kept proof dir: $PROOF_DIR)"
    return 0
  fi
  # Always preserve drill logs even when wiping the work dir.
  if [[ -f "$LOG_MD" || -f "$LOG_JSON" ]]; then
    if [[ "$(cd "$(dirname "$LOG_MD")" 2>/dev/null && pwd)" == "$(cd "$PROOF_DIR" 2>/dev/null && pwd)" ]]; then
      local keep_logs
      keep_logs="$(mktemp -d "${TMPDIR:-/tmp}/aim-drill-logs.XXXXXX")"
      [[ -f "$LOG_MD" ]] && cp -a "$LOG_MD" "$keep_logs/"
      [[ -f "$LOG_JSON" ]] && cp -a "$LOG_JSON" "$keep_logs/"
      echo "(proof dir wiped; logs preserved in $keep_logs)"
      LOG_MD="$keep_logs/$(basename "$LOG_MD")"
      LOG_JSON="$keep_logs/$(basename "$LOG_JSON")"
    fi
  fi
  rm -rf "$PROOF_DIR"
}
trap cleanup EXIT

die_setup() {
  echo "SETUP FAIL: $1" >&2
  exit 2
}

command -v docker >/dev/null 2>&1 || die_setup "docker not found"
[[ -d "$MIGRATIONS_DIR" ]] || die_setup "migrations dir missing: $MIGRATIONS_DIR"
docker info >/dev/null 2>&1 || die_setup "docker daemon not reachable"

start_pg() { # $1 = container name
  if ! docker run -d --name "$1" \
    -e POSTGRES_USER="$DB_USER" \
    -e POSTGRES_PASSWORD="$DB_PASSWORD" \
    -e POSTGRES_DB="$DB_NAME" \
    -p 127.0.0.1::5432 \
    "$IMAGE" >/dev/null; then
    die_setup "could not start postgres container $1 (${IMAGE})"
  fi
  for _ in $(seq 1 90); do
    if docker exec -e PGPASSWORD="$DB_PASSWORD" "$1" \
      psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt -c 'SELECT 1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "$1" 2>&1 | tail -40 || true
  die_setup "postgres $1 never accepted SELECT 1"
}

psql_c() {
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

apply_all_migrations() {
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
  MIGRATION_COUNT="${#FILES[@]}"
}

fmt_duration() {
  local s="$1"
  if (( s < 60 )); then
    printf '%ds' "$s"
  elif (( s < 3600 )); then
    printf '%dm%02ds' $((s / 60)) $((s % 60))
  else
    printf '%dh%02dm%02ds' $((s / 3600)) $(((s % 3600) / 60)) $((s % 60))
  fi
}

echo "============================================================"
echo " backup/restore pilot drill"
echo " drill_id: $DRILL_ID"
echo " started:  $DRILL_STARTED_UTC"
echo " image:    $IMAGE"
echo " proof:    $PROOF_DIR"
echo " log dir:  $DRILL_LOG_DIR"
echo " RTO budget: $(fmt_duration "$PILOT_RTO_SECONDS") (${PILOT_RTO_SECONDS}s)"
echo " RPO target: $(fmt_duration "$PILOT_RPO_SECONDS") (${PILOT_RPO_SECONDS}s scheduled)"
echo "============================================================"

phase_start "seed"
start_pg "$SRC"
apply_all_migrations "$SRC"

# Fixed event timestamps so RPO math is deterministic relative to backup time.
LAST_EVENT_TS="2026-07-01T11:00:00Z"
psql_c "$SRC" <<SQL
INSERT INTO events (event_id, ts, source, tool, session_id, host_ref,
                    user_ref, repo_ref, tokens_in, tokens_out,
                    cost_estimate_usd, match_flags, payload)
VALUES
  ('11111111-1111-1111-1111-111111111111', '2026-07-01T10:00:00Z',
   'collector', 'claude-code', 'sess-drill-1', 'host-hmac-1', 'user-hmac-1',
   'repo-hmac-1', 100, 40, 0.01, '[]'::jsonb,
   '{"schema":"ai-usage-event/v1","proof":"aim-598"}'::jsonb),
  ('22222222-2222-2222-2222-222222222222', '${LAST_EVENT_TS}',
   'collector', 'cursor', 'sess-drill-2', 'host-hmac-2', NULL, NULL,
   NULL, NULL, NULL, '["unattributed"]'::jsonb,
   '{"schema":"ai-usage-event/v1","proof":"aim-598"}'::jsonb);

INSERT INTO findings (finding_id, ts, rule_id, severity, title, subject,
                      evidence, policy_hash, decision, event_id, status)
VALUES ('33333333-3333-3333-3333-333333333333', '2026-07-01T10:00:00Z',
        'restricted-repo-access', 'high', 'Access to restricted repo',
        '{"user_ref":"user-hmac-1"}'::jsonb,
        '{"event_ids":["11111111-1111-1111-1111-111111111111"]}'::jsonb,
        'policyhash-drill', 'observe', '11111111-1111-1111-1111-111111111111',
        'acknowledged');

INSERT INTO retention_audit (run_id, data_class, window_days, cutoff_ts,
                             rows_deleted, dry_run)
VALUES ('44444444-4444-4444-4444-444444444444', 'events', 90,
        '2026-04-01T00:00:00Z', 12, false),
       ('55555555-5555-5555-5555-555555555555', 'findings', 365,
        '2025-07-01T00:00:00Z', 0, true);
SQL

echo '{"batch_id":"b1","events":2,"proof":"aim-598"}' > "$OBJ_SRC/raw/batch-1/events.json"
echo 'deadbeef' > "$OBJ_SRC/raw/batch-1/payload.bin"

SRC_EVENTS=$(psql_c "$SRC" -c "SELECT count(*) FROM events")
SRC_FINDINGS=$(psql_c "$SRC" -c "SELECT count(*) FROM findings")
SRC_AUDIT=$(psql_c "$SRC" -c "SELECT count(*) FROM retention_audit")
SRC_AUDIT_HASH=$(psql_c "$SRC" -c "SELECT md5(string_agg(s, E'\n' ORDER BY s))
  FROM (SELECT (run_id::text || '|' || data_class || '|' || rows_deleted::text || '|' || dry_run::text) AS s
        FROM retention_audit) q")
SRC_FINDING_SAMPLE=$(psql_c "$SRC" -c "SELECT finding_id::text || '|' || rule_id || '|' || status
  FROM findings WHERE finding_id = '33333333-3333-3333-3333-333333333333'")
SRC_OBJ_HASH=$( (cd "$OBJ_SRC" && find . -type f | sort | xargs sha256sum | sha256sum | awk '{print $1}') )
SRC_MAX_TS=$(psql_c "$SRC" -c "SELECT max(ts)::text FROM events")
echo "   source events=$SRC_EVENTS findings=$SRC_FINDINGS audit=$SRC_AUDIT max_ts=$SRC_MAX_TS"
phase_end "seed"

phase_start "backup"
docker exec -e PGPASSWORD="$DB_PASSWORD" "$SRC" \
  pg_dump -U "$DB_USER" -d "$DB_NAME" --format=custom --no-owner \
  > "$DUMP"
cp -a "$OBJ_SRC/." "$PROOF_DIR/backup-minio/"
BACKUP_EPOCH="$(date +%s)"
BACKUP_UTC="$(date -u -d "@$BACKUP_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$BACKUP_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
DUMP_BYTES=$(wc -c < "$DUMP" | tr -d ' ')
check "pg_dump produced non-empty dump" "1" "$( [[ -s "$DUMP" ]] && echo 1 || echo 0 )"
check "object-store mirror has raw batch" "1" \
  "$( [[ -f "$PROOF_DIR/backup-minio/raw/batch-1/events.json" ]] && echo 1 || echo 0 )"
phase_end "backup"

if (( SIMULATE_BACKUP_LAG_S > 0 )); then
  echo "-- simulating backup lag ${SIMULATE_BACKUP_LAG_S}s before incident"
  sleep "$SIMULATE_BACKUP_LAG_S"
fi

# --- Incident: source is gone. RTO clock starts here. ---
phase_start "rto"
INCIDENT_EPOCH="$(date +%s)"
INCIDENT_UTC="$(date -u -d "@$INCIDENT_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$INCIDENT_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
echo "-- INCIDENT declared @ $INCIDENT_UTC (source destroyed)"

phase_start "destroy_source"
docker rm -f "$SRC" >/dev/null
SRC=""  # cleaned
phase_end "destroy_source"

phase_start "restore"
start_pg "$DST"
DST_PRE=$(psql_c "$DST" -c "SELECT count(*) FROM pg_tables WHERE schemaname='public'")
check "destination starts with empty public schema" "0" "$DST_PRE"

docker exec -i -e PGPASSWORD="$DB_PASSWORD" "$DST" \
  pg_restore -U "$DB_USER" -d "$DB_NAME" --no-owner --exit-on-error \
  < "$DUMP"

rm -rf "$OBJ_DST"
mkdir -p "$OBJ_DST"
cp -a "$PROOF_DIR/backup-minio/." "$OBJ_DST/"
phase_end "restore"

phase_start "verify"
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
DST_MAX_TS=$(psql_c "$DST" -c "SELECT max(ts)::text FROM events")

check "events row count" "$SRC_EVENTS" "$DST_EVENTS"
check "findings row count" "$SRC_FINDINGS" "$DST_FINDINGS"
check "retention_audit row count" "$SRC_AUDIT" "$DST_AUDIT"
check "retention_audit sample hash" "$SRC_AUDIT_HASH" "$DST_AUDIT_HASH"
check "finding sample identity" "$SRC_FINDING_SAMPLE" "$DST_FINDING_SAMPLE"
check "object-store content hash" "$SRC_OBJ_HASH" "$DST_OBJ_HASH"
check "schema_migrations ledger restored" "$EXPECTED_LEDGER" "$DST_LEDGER"
check "max event ts preserved" "$SRC_MAX_TS" "$DST_MAX_TS"
phase_end "verify"
phase_end "rto"

RTO_SECONDS="${PHASE_SEC[rto]}"
# Empirical RPO for this drill = lag from backup complete → incident.
RPO_MEASURED_SECONDS=$(( INCIDENT_EPOCH - BACKUP_EPOCH ))
if (( RPO_MEASURED_SECONDS < 0 )); then RPO_MEASURED_SECONDS=0; fi

RTO_OK=0
RPO_OK=0
if (( RTO_SECONDS <= PILOT_RTO_SECONDS )); then RTO_OK=1; else RTO_OK=0; fi
# Scheduled RPO is a process target (nightly). Measured lag in a continuous
# drill is expected near 0; pass scheduled comparison as informational, and
# only fail RPO if measured lag exceeds the scheduled budget (would mean the
# backup was already stale beyond target when the incident hit).
if (( RPO_MEASURED_SECONDS <= PILOT_RPO_SECONDS )); then RPO_OK=1; else RPO_OK=0; fi

OVERALL="PASS"
if (( INTEGRITY_FAILURES > 0 || RTO_OK == 0 || RPO_OK == 0 )); then
  OVERALL="FAIL"
  FAILURES=$((FAILURES + 1))
fi

DRILL_ENDED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TOTAL_SECONDS=$(( $(date +%s) - PHASE_START[seed] ))

# --- Write durable drill log (markdown + json) ---
cat > "$LOG_MD" <<MD
# Backup/restore pilot drill log

| Field | Value |
| --- | --- |
| **drill_id** | \`${DRILL_ID}\` |
| **result** | **${OVERALL}** |
| **started_utc** | ${DRILL_STARTED_UTC} |
| **ended_utc** | ${DRILL_ENDED_UTC} |
| **postgres_image** | \`${IMAGE}\` |
| **migrations_applied** | ${MIGRATION_COUNT:-?} |
| **dump_bytes** | ${DUMP_BYTES} |

## Pilot targets (proposals — see docs/deployment/backup-restore.md)

| Tier | Target | Measured | Verdict |
| --- | --- | --- | --- |
| **RTO** | $(fmt_duration "$PILOT_RTO_SECONDS") (${PILOT_RTO_SECONDS}s) | **$(fmt_duration "$RTO_SECONDS") (${RTO_SECONDS}s)** | $( [[ $RTO_OK -eq 1 ]] && echo PASS || echo FAIL ) |
| **RPO** | $(fmt_duration "$PILOT_RPO_SECONDS") scheduled (${PILOT_RPO_SECONDS}s) | **$(fmt_duration "$RPO_MEASURED_SECONDS") (${RPO_MEASURED_SECONDS}s)** backup age at incident | $( [[ $RPO_OK -eq 1 ]] && echo PASS || echo FAIL ) |

### RTO definition used

Wall-clock from **incident declared** (source Postgres destroyed) until **all
integrity checks pass** on the restored environment. Does **not** include
operator detection time or provisioning a host — only technical restore.

### RPO definition used

\`incident_epoch - backup_epoch\` for this continuous drill (near-zero expected).
Operational pilot RPO is the backup schedule (nightly → 24h max lag). A
stale-at-incident backup older than the scheduled budget fails this check.

## Phase timings

| Phase | Seconds | Human |
| --- | ---: | --- |
| seed (start PG + migrate + seed) | ${PHASE_SEC[seed]} | $(fmt_duration "${PHASE_SEC[seed]}") |
| backup (pg_dump -Fc + object-store mirror) | ${PHASE_SEC[backup]} | $(fmt_duration "${PHASE_SEC[backup]}") |
| destroy_source | ${PHASE_SEC[destroy_source]} | $(fmt_duration "${PHASE_SEC[destroy_source]}") |
| restore (start PG + pg_restore + mirror) | ${PHASE_SEC[restore]} | $(fmt_duration "${PHASE_SEC[restore]}") |
| verify (counts + hashes) | ${PHASE_SEC[verify]} | $(fmt_duration "${PHASE_SEC[verify]}") |
| **RTO (incident → verified)** | **${RTO_SECONDS}** | **$(fmt_duration "$RTO_SECONDS")** |
| total wall (seed → end) | ${TOTAL_SECONDS} | $(fmt_duration "$TOTAL_SECONDS") |

## Integrity checks

| Check | Source | Restored | Verdict |
| --- | --- | --- | --- |
| events count | ${SRC_EVENTS} | ${DST_EVENTS} | $( [[ "$SRC_EVENTS" == "$DST_EVENTS" ]] && echo PASS || echo FAIL ) |
| findings count | ${SRC_FINDINGS} | ${DST_FINDINGS} | $( [[ "$SRC_FINDINGS" == "$DST_FINDINGS" ]] && echo PASS || echo FAIL ) |
| retention_audit count | ${SRC_AUDIT} | ${DST_AUDIT} | $( [[ "$SRC_AUDIT" == "$DST_AUDIT" ]] && echo PASS || echo FAIL ) |
| retention_audit hash | \`${SRC_AUDIT_HASH}\` | \`${DST_AUDIT_HASH}\` | $( [[ "$SRC_AUDIT_HASH" == "$DST_AUDIT_HASH" ]] && echo PASS || echo FAIL ) |
| finding sample | \`${SRC_FINDING_SAMPLE}\` | \`${DST_FINDING_SAMPLE}\` | $( [[ "$SRC_FINDING_SAMPLE" == "$DST_FINDING_SAMPLE" ]] && echo PASS || echo FAIL ) |
| object-store hash | \`${SRC_OBJ_HASH}\` | \`${DST_OBJ_HASH}\` | $( [[ "$SRC_OBJ_HASH" == "$DST_OBJ_HASH" ]] && echo PASS || echo FAIL ) |
| schema_migrations | ${EXPECTED_LEDGER} | ${DST_LEDGER} | $( [[ "$EXPECTED_LEDGER" == "$DST_LEDGER" ]] && echo PASS || echo FAIL ) |
| max(events.ts) | ${SRC_MAX_TS} | ${DST_MAX_TS} | $( [[ "$SRC_MAX_TS" == "$DST_MAX_TS" ]] && echo PASS || echo FAIL ) |

Integrity failures: **${INTEGRITY_FAILURES}**

## Timeline

- backup completed: \`${BACKUP_UTC}\` (epoch ${BACKUP_EPOCH})
- incident declared: \`${INCIDENT_UTC}\` (epoch ${INCIDENT_EPOCH})
- simulate_backup_lag_s: ${SIMULATE_BACKUP_LAG_S}

## How to re-run

\`\`\`sh
./scripts/backup-restore-drill.sh
# write logs into the repo drills folder:
DRILL_LOG_DIR=docs/deployment/drills KEEP_PROOF_DIR=1 ./scripts/backup-restore-drill.sh
\`\`\`

Companion correctness proof (CI, no timing): \`./scripts/backup-restore-proof.sh\`

## Failure handling

On **FAIL**, file a Paperclip issue under the deploy-maturity epic with the
drill_id, failing checks, and this log attached. Do not claim RTO/RPO proven
until a subsequent drill PASSes.
MD

# JSON log (machine-readable)
export DRILL_ID OVERALL DRILL_STARTED_UTC DRILL_ENDED_UTC IMAGE
export MIGRATION_COUNT DUMP_BYTES PILOT_RTO_SECONDS PILOT_RPO_SECONDS
export RTO_SECONDS RPO_MEASURED_SECONDS RTO_OK RPO_OK
export PHASE_SEED="${PHASE_SEC[seed]}"
export PHASE_BACKUP="${PHASE_SEC[backup]}"
export PHASE_DESTROY="${PHASE_SEC[destroy_source]}"
export PHASE_RESTORE="${PHASE_SEC[restore]}"
export PHASE_VERIFY="${PHASE_SEC[verify]}"
export TOTAL_SECONDS INTEGRITY_FAILURES
export SRC_EVENTS DST_EVENTS SRC_FINDINGS DST_FINDINGS SRC_AUDIT DST_AUDIT DST_LEDGER
export BACKUP_UTC INCIDENT_UTC SIMULATE_BACKUP_LAG_S

python3 - "$LOG_JSON" <<'PY'
import json, os, sys

out = sys.argv[1]
env = os.environ
payload = {
    "drill_id": env["DRILL_ID"],
    "result": env["OVERALL"],
    "started_utc": env["DRILL_STARTED_UTC"],
    "ended_utc": env["DRILL_ENDED_UTC"],
    "postgres_image": env["IMAGE"],
    "migrations_applied": int(env.get("MIGRATION_COUNT") or 0),
    "dump_bytes": int(env.get("DUMP_BYTES") or 0),
    "targets": {
        "rto_seconds": int(env["PILOT_RTO_SECONDS"]),
        "rpo_seconds_scheduled": int(env["PILOT_RPO_SECONDS"]),
    },
    "measured": {
        "rto_seconds": int(env["RTO_SECONDS"]),
        "rpo_seconds": int(env["RPO_MEASURED_SECONDS"]),
        "rto_ok": env["RTO_OK"] == "1",
        "rpo_ok": env["RPO_OK"] == "1",
    },
    "phases_seconds": {
        "seed": int(env["PHASE_SEED"]),
        "backup": int(env["PHASE_BACKUP"]),
        "destroy_source": int(env["PHASE_DESTROY"]),
        "restore": int(env["PHASE_RESTORE"]),
        "verify": int(env["PHASE_VERIFY"]),
        "rto": int(env["RTO_SECONDS"]),
        "total": int(env["TOTAL_SECONDS"]),
    },
    "integrity_failures": int(env["INTEGRITY_FAILURES"]),
    "counts": {
        "events_src": env["SRC_EVENTS"].strip(),
        "events_dst": env["DST_EVENTS"].strip(),
        "findings_src": env["SRC_FINDINGS"].strip(),
        "findings_dst": env["DST_FINDINGS"].strip(),
        "audit_src": env["SRC_AUDIT"].strip(),
        "audit_dst": env["DST_AUDIT"].strip(),
        "schema_migrations": env["DST_LEDGER"].strip(),
    },
    "timeline": {
        "backup_utc": env["BACKUP_UTC"],
        "incident_utc": env["INCIDENT_UTC"],
        "simulate_backup_lag_s": int(env["SIMULATE_BACKUP_LAG_S"]),
    },
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"wrote {out}")
PY

echo ""
echo "============================================================"
echo " RESULT: $OVERALL"
echo " RTO measured: $(fmt_duration "$RTO_SECONDS") (${RTO_SECONDS}s)  budget=$(fmt_duration "$PILOT_RTO_SECONDS")  $( [[ $RTO_OK -eq 1 ]] && echo OK || echo EXCEEDED )"
echo " RPO measured: $(fmt_duration "$RPO_MEASURED_SECONDS") (${RPO_MEASURED_SECONDS}s)  scheduled=$(fmt_duration "$PILOT_RPO_SECONDS")  $( [[ $RPO_OK -eq 1 ]] && echo OK || echo EXCEEDED )"
echo " integrity failures: $INTEGRITY_FAILURES"
echo " drill log (md):   $LOG_MD"
echo " drill log (json): $LOG_JSON"
echo "============================================================"

if [[ "$OVERALL" != "PASS" ]]; then
  exit 1
fi
exit 0
