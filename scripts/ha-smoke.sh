#!/usr/bin/env bash
# — multi-replica HA smoke for ingest (compose-shaped).
#
# What this proves on a live aim-local (or similar) stack:
#   1. A second ingest replica can join the same Docker network and accept work.
#   2. Dual-write of the same event_id to both replicas yields exactly one row
#      (event_id PRIMARY KEY — no dual-write corruption).
#   3. After killing the secondary replica, host-published ingest continues to
#      accept batches (surviving replica path).
#   4. After killing the primary and promoting the secondary to the host port,
#      ingest recovers and accepts batches again.
#
# Usage:
#   ./scripts/ha-smoke.sh
# Env:
#   COMPOSE_PROJECT   default aim-local
#   INGEST_URL        default http://127.0.0.1:8080
#   INGEST_TOKEN      default dev-token-change-me
#   PRIMARY_CONTAINER default ${COMPOSE_PROJECT}-ingest-1
#   NETWORK           auto-detected from primary
#   KEEP_REPLICA=1    leave secondary running on exit
#
# Requires: docker, curl, python3. Exits non-zero on any FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${COMPOSE_PROJECT:-aim-local}"
PRIMARY="${PRIMARY_CONTAINER:-${PROJECT}-ingest-1}"
INGEST_URL="${INGEST_URL:-http://127.0.0.1:8080}"
INGEST_TOKEN="${INGEST_TOKEN:-dev-token-change-me}"
SECONDARY="${SECONDARY_CONTAINER:-aim-553-ha-ingest-2}"
PROOF_MARKER="aim553-ha"

FAILURES=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

cleanup() {
  if [[ "${KEEP_REPLICA:-0}" != "1" ]]; then
    docker rm -f "$SECONDARY" >/dev/null 2>&1 || true
  fi
  # If primary was stopped, try to start it back so the shared stack recovers.
  if docker inspect "$PRIMARY" >/dev/null 2>&1; then
    local st
    st="$(docker inspect -f '{{.State.Status}}' "$PRIMARY" 2>/dev/null || echo missing)"
    if [[ "$st" != "running" ]]; then
      docker start "$PRIMARY" >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 2; }; }
need docker
need curl
need python3

if ! docker inspect "$PRIMARY" >/dev/null 2>&1; then
  echo "FAIL: primary ingest container not found: $PRIMARY" >&2
  echo "Start the local stack (compose project $PROJECT) first." >&2
  exit 2
fi

NETWORK="${NETWORK:-$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$PRIMARY")}"
IMAGE="$(docker inspect -f '{{.Config.Image}}' "$PRIMARY")"
PRIMARY_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PRIMARY")"

echo "== HA smoke =="
echo "primary=$PRIMARY ip=$PRIMARY_IP network=$NETWORK image=$IMAGE"

# Health on published port
code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$INGEST_URL/healthz" || true)"
if [[ "$code" == "200" ]]; then
  pass "primary healthz via $INGEST_URL ($code)"
else
  fail "primary healthz via $INGEST_URL (got $code)"
fi

# Build env file for secondary (same config as primary, no host port).
ENV_FILE="$(mktemp "${TMPDIR:-/tmp}/aim553-ha-env.XXXXXX")"
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$PRIMARY" >"$ENV_FILE"

docker rm -f "$SECONDARY" >/dev/null 2>&1 || true
if ! docker run -d \
  --name "$SECONDARY" \
  --network "$NETWORK" \
  --network-alias "ingest-ha-2" \
  --env-file "$ENV_FILE" \
  "$IMAGE" >/dev/null; then
  fail "could not start secondary ingest"
  rm -f "$ENV_FILE"
  exit 1
fi
rm -f "$ENV_FILE"

# Wait for secondary /healthz on its container IP
SEC_IP=""
for _ in $(seq 1 60); do
  SEC_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SECONDARY" 2>/dev/null || true)"
  if [[ -n "$SEC_IP" ]] && docker exec "$SECONDARY" wget -q -O- "http://127.0.0.1:8080/healthz" >/dev/null 2>&1; then
    break
  fi
  # node image may not have wget — try curl inside or host-side via network
  if [[ -n "$SEC_IP" ]] && docker run --rm --network "$NETWORK" curlimages/curl:8.5.0 \
      -sS -o /dev/null -w '' --max-time 2 "http://${SEC_IP}:8080/healthz" 2>/dev/null; then
    break
  fi
  # Fallback: docker exec node -e fetch
  if docker exec "$SECONDARY" node -e 'fetch("http://127.0.0.1:8080/healthz").then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))' 2>/dev/null; then
    SEC_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SECONDARY")"
    break
  fi
  sleep 1
done
if [[ -z "$SEC_IP" ]]; then
  fail "secondary never got an IP / healthy"
  docker logs "$SECONDARY" 2>&1 | tail -40 || true
  exit 1
fi
pass "secondary running at $SEC_IP"

post_event_to() {
  # $1 = base URL (http://ip:8080), $2 = event_id
  local base="$1" eid="$2"
  local hex ts
  hex="$(python3 -c 'print("a"*64)')"
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local code
  code="$(curl -sS -o /tmp/aim553-post.json -w '%{http_code}' --max-time 8 \
    -H "authorization: Bearer ${INGEST_TOKEN}" -H 'content-type: application/json' \
    -d "{\"events\":[{\"schema_version\":\"1.0\",\"event_id\":\"${eid}\",\"ts\":\"${ts}\",\"host_ref\":\"${hex}\",\"user_ref\":\"${hex}\",\"tool\":\"claude_code\",\"tool_version\":\"0.0.0-aim553\",\"model\":\"x\",\"provider\":\"anthropic\",\"session_id\":\"00000000-0000-4000-8000-000000000053\",\"tokens_in\":1,\"tokens_out\":1,\"match_flags\":[],\"source\":\"endpoint\",\"repo_ref\":\"${hex}\"}]}" \
    "${base}/v1/events" || true)"
  if [[ "$code" == "200" || "$code" == "202" ]]; then
    return 0
  fi
  echo "post_event_to ${base} -> HTTP ${code} body=$(head -c 200 /tmp/aim553-post.json 2>/dev/null || true)" >&2
  return 1
}

# Dual-write: same event_id to both replicas
EID="$(python3 - <<'PY2'
import uuid; print(uuid.uuid4())
PY2
)"
echo "-- dual-write event_id=$EID"
if post_event_to "http://${PRIMARY_IP}:8080" "$EID"; then
  pass "post to primary IP"
else
  fail "post to primary IP"
fi
if post_event_to "http://${SEC_IP}:8080" "$EID"; then
  pass "post same event_id to secondary IP (expect dedupe)"
else
  fail "post same event_id to secondary IP"
fi

# Count rows for that event_id via postgres
PG="$(docker ps --format '{{.Names}}' | grep -E "${PROJECT}-postgres|aim-local-postgres" | head -1 || true)"
if [[ -z "$PG" ]]; then
  PG="$(docker ps --format '{{.Names}}' | grep postgres | head -1 || true)"
fi
if [[ -n "$PG" ]]; then
  COUNT="$(docker exec "$PG" psql -U aim -d aim -v ON_ERROR_STOP=1 -qAt \
    -c "SELECT count(*) FROM events WHERE event_id = '$EID';" | tr -d '[:space:]')"
  if [[ "$COUNT" == "1" ]]; then
    pass "dual-write produced exactly 1 row (got $COUNT)"
  else
    fail "dual-write row count expected 1 got [$COUNT]"
  fi
else
  fail "could not find postgres container to verify dual-write"
fi


# Kill secondary; primary published port must still work
echo "-- kill secondary; traffic via host port"
docker stop "$SECONDARY" >/dev/null
ok=0
for i in $(seq 1 10); do
  EID2="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  if code="$(curl -sS -o /tmp/aim553-ha-body.json -w '%{http_code}' --max-time 5 \
      -H "authorization: Bearer $INGEST_TOKEN" -H 'content-type: application/json' \
      -d "{\"events\":[{\"schema_version\":\"1.0\",\"event_id\":\"$EID2\",\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"host_ref\":\"$(printf 'a%.0s' {1..64})\",\"user_ref\":\"$(printf 'b%.0s' {1..64})\",\"tool\":\"claude_code\",\"tool_version\":\"0.0.0-aim553\",\"model\":\"x\",\"provider\":\"anthropic\",\"session_id\":\"00000000-0000-4000-8000-000000000054\",\"tokens_in\":1,\"tokens_out\":1,\"match_flags\":[],\"source\":\"endpoint\",\"repo_ref\":\"$(printf 'c%.0s' {1..64})\"}]}" \
      "$INGEST_URL/v1/events")"; then
    if [[ "$code" == "200" || "$code" == "202" ]]; then ok=1; break; fi
  fi
  sleep 1
done
if [[ "$ok" == "1" ]]; then
  pass "host ingest accepts events after secondary kill (http $code)"
else
  fail "host ingest failed after secondary kill"
fi

# Kill primary; promote secondary to host port 8080 and prove recovery.
# measure app-tier RTO from primary stop → first successful post.
# Kill primary; promote secondary to host port 8080 and prove recovery
echo "-- kill primary; promote secondary onto host :8080"
docker start "$SECONDARY" >/dev/null
# wait healthy
for _ in $(seq 1 30); do
  if docker exec "$SECONDARY" node -e 'fetch("http://127.0.0.1:8080/healthz").then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))' 2>/dev/null; then
    break
  fi
  sleep 1
done
RTO_START_NS="$(date +%s%N)"
docker stop "$PRIMARY" >/dev/null
# Map secondary to host 8080 (primary held it)
docker rm -f "${SECONDARY}-published" >/dev/null 2>&1 || true
# Prefer docker network connect + publish by re-creating with -p
# Extract config again and re-run with publish
ENV_FILE="$(mktemp "${TMPDIR:-/tmp}/aim553-ha-env.XXXXXX")"
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SECONDARY" >"$ENV_FILE"
docker rm -f "$SECONDARY" >/dev/null
if docker run -d \
  --name "$SECONDARY" \
  --network "$NETWORK" \
  -p 127.0.0.1:8080:8080 \
  --env-file "$ENV_FILE" \
  "$IMAGE" >/dev/null; then
  pass "secondary republished on 127.0.0.1:8080"
else
  fail "could not republish secondary on host 8080"
fi
rm -f "$ENV_FILE"

ok=0
RTO_MS=""
for i in $(seq 1 40); do
  if curl -sS -o /dev/null -w '' --max-time 2 "$INGEST_URL/healthz" 2>/dev/null; then
    EID3="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    code="$(curl -sS -o /tmp/aim553-ha-body.json -w '%{http_code}' --max-time 5 \
      -H "authorization: Bearer $INGEST_TOKEN" -H 'content-type: application/json' \
      -d "{\"events\":[{\"schema_version\":\"1.0\",\"event_id\":\"$EID3\",\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"host_ref\":\"$(printf 'a%.0s' {1..64})\",\"user_ref\":\"$(printf 'b%.0s' {1..64})\",\"tool\":\"claude_code\",\"tool_version\":\"0.0.0-aim553\",\"model\":\"x\",\"provider\":\"anthropic\",\"session_id\":\"00000000-0000-4000-8000-000000000055\",\"tokens_in\":1,\"tokens_out\":1,\"match_flags\":[],\"source\":\"endpoint\",\"repo_ref\":\"$(printf 'c%.0s' {1..64})\"}]}" \
      "$INGEST_URL/v1/events" || true)"
    if [[ "$code" == "200" || "$code" == "202" ]]; then
      ok=1
      RTO_END_NS="$(date +%s%N)"
      RTO_MS=$(( (RTO_END_NS - RTO_START_NS) / 1000000 ))
      break
    fi
    if [[ "$code" == "200" || "$code" == "202" ]]; then ok=1; break; fi
  fi
  sleep 1
done
if [[ "$ok" == "1" ]]; then
  pass "ingest accepts events after primary kill + secondary promote (http $code)"
  pass "app-tier RTO measured: ${RTO_MS}ms (primary stop → first successful post)"
  echo "RTO_MS=${RTO_MS}"
else
  fail "ingest did not recover after primary kill"
fi

# Restore primary for shared stack hygiene
echo "-- restore primary compose container"
docker rm -f "$SECONDARY" >/dev/null 2>&1 || true
docker start "$PRIMARY" >/dev/null 2>&1 || true
for _ in $(seq 1 40); do
  if curl -sS -o /dev/null -w '' --max-time 2 "$INGEST_URL/healthz" 2>/dev/null; then
    pass "primary restored on $INGEST_URL"
    break
  fi
  sleep 1
done

echo "=="
if (( FAILURES > 0 )); then
  echo "RESULT: FAIL (${FAILURES} check(s) failed)"
  exit 1
fi
echo "RESULT: PASS — multi-replica dual-write safe; kill drill recovered"
exit 0
