#!/usr/bin/env bash
# — compose chaos / failure-injection drill (safe subset).
#
# Extends HA smoke with process-kill recovery timings and measurable
# no-silent-loss checks against Postgres.
#
# Drills (default):
#   F1  kill ingest  → start → health + write + pre-marker retained
#   F2  kill api     → start → /api/health
#   F3  ingest crash-loop ×3 → final write OK + markers retained
#   F4  brief postgres pause → unpause → write OK (SKIP_PG=1 to skip)
#   F5  brief minio stop    → start  → write OK (SKIP_MINIO=1 to skip)
#
# Usage:
#   ./scripts/chaos-drill.sh
# Env:
#   COMPOSE_PROJECT   default aim-local
#   INGEST_URL        default http://127.0.0.1:8080
#   API_URL           default http://127.0.0.1:8181
#   INGEST_TOKEN      default dev-token-change-me
#   PG_PAUSE_SECONDS  default 12
#   MINIO_DOWN_SECONDS default 12
#   SKIP_PG=1 SKIP_MINIO=1
#   KEEP_DOWN=1       do not restart on failure paths (debug only — not for CI)
#
# Requires: docker, curl, python3. Exits non-zero on any FAIL.
# Always attempts to restore stopped/paused containers on EXIT.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${COMPOSE_PROJECT:-aim-local}"
INGEST_URL="${INGEST_URL:-http://127.0.0.1:8080}"
API_URL="${API_URL:-http://127.0.0.1:8181}"
INGEST_TOKEN="${INGEST_TOKEN:-dev-token-change-me}"
PG_PAUSE_SECONDS="${PG_PAUSE_SECONDS:-12}"
MINIO_DOWN_SECONDS="${MINIO_DOWN_SECONDS:-12}"
PROOF_PREFIX="aim635chaos"

FAILURES=0
declare -a TIMINGS=()
declare -a MARKERS=()

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }
note() { echo "NOTE: $1"; }
record_timing() {
  # $1=name $2=ms
  TIMINGS+=("$1=$2")
  echo "RECOVERY_MS_$1=$2"
}

now_ms() {
  python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 2; }; }
need docker
need curl
need python3

find_container() {
  # $1=service name fragment (ingest|api|postgres|minio)
  local svc="$1" name
  name="$(docker ps -a --format '{{.Names}}' | grep -E "^${PROJECT}-${svc}-[0-9]+$" | head -1 || true)"
  if [[ -z "$name" ]]; then
    name="$(docker ps -a --format '{{.Names}}' | grep -E "${PROJECT}.*${svc}" | head -1 || true)"
  fi
  if [[ -z "$name" ]]; then
    name="$(docker ps -a --format '{{.Names}}' | grep -E "${svc}" | grep -E "${PROJECT}|aim-local|stack-aim" | head -1 || true)"
  fi
  printf '%s' "$name"
}

ensure_running() {
  local c="$1"
  [[ -n "$c" ]] || return 1
  local st
  st="$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)"
  if [[ "$st" == "paused" ]]; then
    docker unpause "$c" >/dev/null 2>&1 || true
  fi
  if [[ "$st" != "running" && "$st" != "paused" ]]; then
    docker start "$c" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  if [[ "${KEEP_DOWN:-0}" == "1" ]]; then
    note "KEEP_DOWN=1 — skipping restore"
    return 0
  fi
  echo "-- cleanup: restore containers"
  for c in "${INGEST_CTN:-}" "${API_CTN:-}" "${PG_CTN:-}" "${MINIO_CTN:-}"; do
    [[ -n "$c" ]] || continue
    ensure_running "$c" || true
  done
}
trap cleanup EXIT

INGEST_CTN="$(find_container ingest)"
API_CTN="$(find_container api)"
PG_CTN="$(find_container postgres)"
MINIO_CTN="$(find_container minio)"

echo "== chaos drill =="
echo "project=$PROJECT ingest_url=$INGEST_URL api_url=$API_URL"
echo "containers: ingest=$INGEST_CTN api=$API_CTN postgres=$PG_CTN minio=$MINIO_CTN"

if [[ -z "$INGEST_CTN" || -z "$API_CTN" ]]; then
  echo "FAIL: need running compose ingest + api under project $PROJECT" >&2
  exit 2
fi
if ! docker inspect -f '{{.State.Running}}' "$INGEST_CTN" 2>/dev/null | grep -q true; then
  echo "FAIL: ingest not running: $INGEST_CTN" >&2
  exit 2
fi
if ! docker inspect -f '{{.State.Running}}' "$API_CTN" 2>/dev/null | grep -q true; then
  echo "FAIL: api not running: $API_CTN" >&2
  exit 2
fi

wait_http() {
  # $1=url $2=timeout_sec $3=optional label
  local url="$1" timeout="${2:-60}" label="${3:-http}"
  local t0 t1 code i
  t0="$(now_ms)"
  for i in $(seq 1 "$timeout"); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "$url" 2>/dev/null || true)"
    if [[ "$code" == "200" ]]; then
      t1="$(now_ms)"
      echo "$((t1 - t0))"
      return 0
    fi
    sleep 1
  done
  t1="$(now_ms)"
  echo "$((t1 - t0))"
  return 1
}

post_event() {
  # $1=event_id — prints http code on stdout via global, returns 0 on 200/202
  local eid="$1"
  local hex ts code body
  hex="$(python3 -c 'print("a"*64)')"
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  body="$(python3 - <<PY
import json
print(json.dumps({
  "events": [{
    "schema_version": "1.0",
    "event_id": "$eid",
    "ts": "$ts",
    "host_ref": "$hex",
    "user_ref": "$hex",
    "tool": "claude_code",
    "tool_version": "0.0.0-${PROOF_PREFIX}",
    "model": "x",
    "provider": "anthropic",
    "session_id": "00000000-0000-4000-8000-000000000635",
    "tokens_in": 1,
    "tokens_out": 1,
    "match_flags": [],
    "source": "endpoint",
    "repo_ref": "$hex",
  }]
}))
PY
)"
  code="$(curl -sS -o /tmp/aim635-chaos-post.json -w '%{http_code}' --max-time 8 \
    -H "authorization: Bearer ${INGEST_TOKEN}" -H 'content-type: application/json' \
    -d "$body" \
    "${INGEST_URL}/v1/events" 2>/dev/null || echo "000")"
  LAST_POST_CODE="$code"
  if [[ "$code" == "200" || "$code" == "202" ]]; then
    return 0
  fi
  return 1
}

new_eid() {
  python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
}

pg_count() {
  local eid="$1" count
  if [[ -z "${PG_CTN:-}" ]]; then
    echo "?"
    return 1
  fi
  count="$(docker exec "$PG_CTN" psql -U aim -d aim -v ON_ERROR_STOP=1 -qAt \
    -c "SELECT count(*) FROM events WHERE event_id = '$eid';" 2>/dev/null | tr -d '[:space:]' || echo err)"
  printf '%s' "$count"
}

assert_marker_retained() {
  local eid="$1" label="$2" c
  if [[ -z "${PG_CTN:-}" ]]; then
    fail "$label: no postgres container for silent-loss check"
    return
  fi
  c="$(pg_count "$eid")"
  if [[ "$c" == "1" ]]; then
    pass "$label: marker $eid retained (count=1)"
  else
    fail "$label: marker $eid expected count=1 got [$c]"
  fi
}

# ---- baseline ----
echo "-- baseline health"
ms="$(wait_http "${INGEST_URL}/healthz" 30 ingest_baseline)" && pass "ingest healthz (${ms}ms probe)" || fail "ingest healthz not ready"
ms="$(wait_http "${API_URL}/api/health" 30 api_baseline)" && pass "api /api/health (${ms}ms probe)" || fail "api /api/health not ready"

# Pre-fault markers for silent-loss
echo "-- seed pre-fault markers"
for i in 1 2 3; do
  eid="$(new_eid)"
  if post_event "$eid"; then
    MARKERS+=("$eid")
    pass "seeded marker $i event_id=$eid (http $LAST_POST_CODE)"
  else
    fail "could not seed marker $i (http ${LAST_POST_CODE:-?})"
  fi
done
# give postgres a beat
sleep 1
for eid in "${MARKERS[@]:-}"; do
  assert_marker_retained "$eid" "pre-fault"
done

# ---- F1 ingest kill ----
echo "-- F1: kill ingest + recover"
t_kill="$(now_ms)"
docker kill "$INGEST_CTN" >/dev/null
docker start "$INGEST_CTN" >/dev/null
if ms="$(wait_http "${INGEST_URL}/healthz" 90 ingest_f1)"; then
  record_timing "INGEST_KILL" "$ms"
  pass "F1 ingest recovered in ${ms}ms"
else
  record_timing "INGEST_KILL" "$ms"
  fail "F1 ingest did not recover within timeout (${ms}ms)"
fi
eid="$(new_eid)"
ok=0
for _ in $(seq 1 20); do
  if post_event "$eid"; then ok=1; break; fi
  sleep 1
done
if [[ "$ok" == "1" ]]; then
  pass "F1 post-recovery write ok (http $LAST_POST_CODE event_id=$eid)"
  sleep 1
  assert_marker_retained "$eid" "F1 post-write"
else
  fail "F1 post-recovery write failed"
fi
for eid in "${MARKERS[@]:-}"; do
  assert_marker_retained "$eid" "F1 silent-loss"
done

# ---- F2 api kill ----
echo "-- F2: kill api + recover"
docker kill "$API_CTN" >/dev/null
docker start "$API_CTN" >/dev/null
if ms="$(wait_http "${API_URL}/api/health" 90 api_f2)"; then
  record_timing "API_KILL" "$ms"
  pass "F2 api recovered in ${ms}ms"
else
  record_timing "API_KILL" "$ms"
  fail "F2 api did not recover within timeout (${ms}ms)"
fi
# Ingest should still have been independent; re-check + write
if post_event "$(new_eid)"; then
  pass "F2 ingest still accepting while/after api recovery (http $LAST_POST_CODE)"
else
  # retry once after short wait — api kill should not kill ingest
  sleep 2
  if post_event "$(new_eid)"; then
    pass "F2 ingest accepting after brief retry (http $LAST_POST_CODE)"
  else
    fail "F2 ingest not accepting after api kill (http ${LAST_POST_CODE:-?})"
  fi
fi
for eid in "${MARKERS[@]:-}"; do
  assert_marker_retained "$eid" "F2 silent-loss"
done

# ---- F3 ingest crash-loop ----
echo "-- F3: ingest crash-loop ×3"
t0="$(now_ms)"
for i in 1 2 3; do
  docker kill "$INGEST_CTN" >/dev/null 2>&1 || true
  docker start "$INGEST_CTN" >/dev/null 2>&1 || true
  sleep 1
done
if ms="$(wait_http "${INGEST_URL}/healthz" 90 ingest_f3)"; then
  # total wall from start of loop
  t1="$(now_ms)"
  total=$((t1 - t0))
  record_timing "INGEST_CRASHLOOP" "$total"
  pass "F3 ingest healthy after crash-loop (final probe ${ms}ms, wall ${total}ms)"
else
  t1="$(now_ms)"
  total=$((t1 - t0))
  record_timing "INGEST_CRASHLOOP" "$total"
  fail "F3 ingest unhealthy after crash-loop (wall ${total}ms)"
fi
eid="$(new_eid)"
ok=0
for _ in $(seq 1 20); do
  if post_event "$eid"; then ok=1; break; fi
  sleep 1
done
if [[ "$ok" == "1" ]]; then
  pass "F3 post-loop write ok (event_id=$eid)"
else
  fail "F3 post-loop write failed"
fi
for eid in "${MARKERS[@]:-}"; do
  assert_marker_retained "$eid" "F3 silent-loss"
done

# ---- F4 postgres brief pause ----
if [[ "${SKIP_PG:-0}" == "1" ]]; then
  note "SKIP_PG=1 — skipping F4"
elif [[ -z "${PG_CTN:-}" ]]; then
  note "no postgres container — skipping F4"
else
  echo "-- F4: postgres pause ${PG_PAUSE_SECONDS}s"
  docker pause "$PG_CTN" >/dev/null
  sleep "$PG_PAUSE_SECONDS"
  t0="$(now_ms)"
  docker unpause "$PG_CTN" >/dev/null
  # wait ingest health (may flap) then successful write
  wait_http "${INGEST_URL}/healthz" 60 ingest_f4 >/dev/null || true
  eid="$(new_eid)"
  ok=0
  for _ in $(seq 1 60); do
    if post_event "$eid"; then ok=1; break; fi
    sleep 1
  done
  t1="$(now_ms)"
  ms=$((t1 - t0))
  record_timing "POSTGRES_UNPAUSE" "$ms"
  if [[ "$ok" == "1" ]]; then
    pass "F4 write after postgres unpause in ${ms}ms (event_id=$eid)"
    sleep 1
    assert_marker_retained "$eid" "F4 post-write"
  else
    fail "F4 no successful write within ${ms}ms after unpause"
  fi
  for eid in "${MARKERS[@]:-}"; do
    assert_marker_retained "$eid" "F4 silent-loss"
  done
fi

# ---- F5 minio outage ----
if [[ "${SKIP_MINIO:-0}" == "1" ]]; then
  note "SKIP_MINIO=1 — skipping F5"
elif [[ -z "${MINIO_CTN:-}" ]]; then
  note "no minio container — skipping F5"
else
  echo "-- F5: minio stop ${MINIO_DOWN_SECONDS}s (metadata path should survive)"
  docker stop "$MINIO_CTN" >/dev/null
  sleep 2
  eid_down="$(new_eid)"
  # May succeed (DB-first) or fail — either way we record and require post-restore success + markers
  if post_event "$eid_down"; then
    pass "F5 write while minio down (http $LAST_POST_CODE) — metadata path survived"
    MARKERS+=("$eid_down")
  else
    note "F5 write while minio down failed (http ${LAST_POST_CODE:-?}) — acceptable if archival is sync-critical; will require post-restore write"
  fi
  sleep "$MINIO_DOWN_SECONDS"
  t0="$(now_ms)"
  docker start "$MINIO_CTN" >/dev/null
  # minio health is internal; wait ingest + write
  wait_http "${INGEST_URL}/healthz" 60 ingest_f5 >/dev/null || true
  eid="$(new_eid)"
  ok=0
  for _ in $(seq 1 45); do
    if post_event "$eid"; then ok=1; break; fi
    sleep 1
  done
  t1="$(now_ms)"
  ms=$((t1 - t0))
  record_timing "MINIO_RESTORE" "$ms"
  if [[ "$ok" == "1" ]]; then
    pass "F5 write after minio restore in ${ms}ms (event_id=$eid)"
  else
    fail "F5 no successful write after minio restore (${ms}ms)"
  fi
  for eid in "${MARKERS[@]:-}"; do
    assert_marker_retained "$eid" "F5 silent-loss"
  done
fi

# ---- final restore health ----
echo "-- final health"
ensure_running "$INGEST_CTN"
ensure_running "$API_CTN"
[[ -n "${PG_CTN:-}" ]] && ensure_running "$PG_CTN"
[[ -n "${MINIO_CTN:-}" ]] && ensure_running "$MINIO_CTN"
ms="$(wait_http "${INGEST_URL}/healthz" 60 final_ingest)" && pass "final ingest health (${ms}ms)" || fail "final ingest health"
ms="$(wait_http "${API_URL}/api/health" 60 final_api)" && pass "final api health (${ms}ms)" || fail "final api health"

echo "=="
echo "TIMINGS: ${TIMINGS[*]:-none}"
if (( FAILURES > 0 )); then
  echo "RESULT: FAIL (${FAILURES} check(s) failed)"
  exit 1
fi
echo "RESULT: PASS — chaos subset recovered; markers retained; timings recorded"
exit 0
