#!/usr/bin/env bash
# AI Monitoring — device enrollment + heartbeat for macOS (AIM-743).
# Runs as root on the LaunchDaemon schedule. Contract:
# docs/deployment/enrollment-and-heartbeat.md
set -uo pipefail

CONFIG_DIR="${AIM_CONFIG_DIR:-/etc/aim-collector}"
CONFIG_JSON="$CONFIG_DIR/config.json"
HOST_ID_FILE="$CONFIG_DIR/host_id"
ENROLL_TOKEN_FILE="$CONFIG_DIR/enroll-token"
DEVICE_TOKEN_FILE="$CONFIG_DIR/device-token"
COLLECTOR_VERSION="${AIM_COLLECTOR_VERSION:-}"
if [ -z "$COLLECTOR_VERSION" ] && [ -r "$CONFIG_DIR/version" ]; then
  COLLECTOR_VERSION="$(tr -d '[:space:]' < "$CONFIG_DIR/version")"
fi
COLLECTOR_VERSION="${COLLECTOR_VERSION:-0.1.0}"
RING="${AIM_RING:-pilot}"

log() { printf '[aim-heartbeat-macos] %s\n' "$*"; }

[ -r "$CONFIG_JSON" ] || { log "no config at $CONFIG_JSON; skipping"; exit 0; }

INGEST_URL="${AIM_INGEST_URL:-$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ingest_url",""))' "$CONFIG_JSON" 2>/dev/null)}"
[ -n "$INGEST_URL" ] || { log "no ingest_url configured; skipping"; exit 0; }
INGEST_URL="${INGEST_URL%/}"

if [ ! -s "$HOST_ID_FILE" ]; then
  umask 022
  python3 -c 'import uuid; print(uuid.uuid4())' > "$HOST_ID_FILE"
fi
HOST_ID="$(tr -d '[:space:]' < "$HOST_ID_FILE")"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"

os_string() {
  local ver
  ver="$(sw_vers -productVersion 2>/dev/null || true)"
  if [ -n "$ver" ]; then
    printf 'macos-%s\n' "$ver"
  else
    printf 'macos\n'
  fi
}
OS_STRING="$(os_string)"

if [ ! -s "$DEVICE_TOKEN_FILE" ]; then
  if [ ! -s "$ENROLL_TOKEN_FILE" ]; then
    log "no device token and no enroll-token; staying on pilot event last-seen coverage"
    exit 0
  fi
  ENROLL_TOKEN="$(tr -d '[:space:]' < "$ENROLL_TOKEN_FILE")"
  body="$(python3 -c 'import json,sys; print(json.dumps({"host_id":sys.argv[1],"hostname":sys.argv[2],"os":sys.argv[3],"collector_version":sys.argv[4],"ring":sys.argv[5]}))' \
    "$HOST_ID" "$HOSTNAME_SHORT" "$OS_STRING" "$COLLECTOR_VERSION" "$RING")"
  resp="$(curl -sS -m 20 -X POST "$INGEST_URL/v1/enroll" \
    -H "Authorization: Bearer $ENROLL_TOKEN" -H "Content-Type: application/json" \
    -d "$body" 2>/dev/null)" || { log "enroll request failed; will retry next cycle"; exit 0; }
  token="$(printf '%s' "$resp" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("device_token") or "")
except Exception: print("")' 2>/dev/null)"
  if [ -z "$token" ]; then
    log "enroll returned no device_token; skipping"
    exit 0
  fi
  umask 077
  printf '%s' "$token" > "$DEVICE_TOKEN_FILE"
  chmod 0600 "$DEVICE_TOKEN_FILE"
  log "device enrolled; per-device token stored"
fi

DEVICE_TOKEN="$(tr -d '[:space:]' < "$DEVICE_TOKEN_FILE")"
spooled="$(find /Users/*/.aim-collector/spool /var/root/.aim-collector/spool -type f 2>/dev/null | wc -l | tr -d ' ')"
hb_body="$(python3 -c 'import json,sys; print(json.dumps({"host_id":sys.argv[1],"collector_version":sys.argv[2],"os":sys.argv[3],"counters":{"events_spooled":int(sys.argv[4])}}))' \
  "$HOST_ID" "$COLLECTOR_VERSION" "$OS_STRING" "${spooled:-0}")"

code="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST "$INGEST_URL/v1/heartbeat" \
  -H "Authorization: Bearer $DEVICE_TOKEN" -H "Content-Type: application/json" \
  -d "$hb_body" 2>/dev/null)" || { log "heartbeat request failed; will retry next cycle"; exit 0; }

case "$code" in
  200) log "heartbeat ok" ;;
  401) log "heartbeat unauthorized (token revoked?); dropping device token for re-enroll"
       rm -f "$DEVICE_TOKEN_FILE" ;;
  *)   log "heartbeat returned HTTP $code; will retry next cycle" ;;
esac
exit 0
