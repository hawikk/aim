#!/usr/bin/env bash
# progressive delivery gate check (promote / abort recommendation).
# Env:
#   INGEST_URL / BASE_URL  default http://127.0.0.1:8080
#   API_URL                default same as BASE_URL
#   INGEST_TOKEN           optional canary event
#   STRICT=1               treat missing api health as FAIL
set -euo pipefail

BASE_URL="${BASE_URL:-${INGEST_URL:-http://127.0.0.1:8080}}"
INGEST_URL="${INGEST_URL:-$BASE_URL}"
API_URL="${API_URL:-$BASE_URL}"
STRICT="${STRICT:-0}"
FAILURES=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

code() { curl -sf -o /dev/null -w "%{http_code}" "$1" 2>/dev/null || echo "000"; }

echo "== progressive gate check =="
echo "ingest: $INGEST_URL"
echo "api:    $API_URL"

IC=$(code "$INGEST_URL/healthz")
if [[ "$IC" == "200" ]]; then pass "ingest /healthz"; else fail "ingest /healthz ($IC)"; fi

AC=$(code "$API_URL/api/health")
if [[ "$AC" == "200" ]]; then
  pass "api /api/health"
elif [[ "$STRICT" == "1" ]]; then
  fail "api /api/health ($AC)"
else
  echo "WARN: api /api/health ($AC) — set STRICT=1 to fail closed"
fi

if [[ -n "${INGEST_TOKEN:-}" ]]; then
  ID="prog-635-$(date +%s)"
  HTTP=$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $INGEST_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"event_id\":\"$ID\",\"schema_version\":\"1\",\"tool\":\"claude_code\",\"event_type\":\"session_start\",\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
    "$INGEST_URL/v1/events" 2>/dev/null || echo "000")
  if [[ "$HTTP" == "200" || "$HTTP" == "201" || "$HTTP" == "202" || "$HTTP" == "204" ]]; then
    pass "canary event accepted ($HTTP)"
  else
    fail "canary event ($HTTP)"
  fi
else
  echo "INFO: INGEST_TOKEN unset — skipped canary event"
fi

echo "=="
if [[ "$FAILURES" -eq 0 ]]; then
  echo "RECOMMENDATION: PROMOTE (gates green)"
  echo "RESULT: PASS"
  exit 0
fi
echo "RECOMMENDATION: ABORT (gates red) — do not expand rings / rollback canary"
echo "RESULT: FAIL — $FAILURES gate(s) red"
exit 1
