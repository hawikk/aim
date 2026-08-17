#!/usr/bin/env bash
# AI Monitoring — device enrollment + heartbeat (AIM-28).
#
# Runs as root on the device schedule (systemd timer / cron), once per cycle,
# independent of per-user transcript scans. On first run it enrolls the device
# (if an enrollment token is present) to obtain a per-device token, then posts a
# liveness heartbeat so the fleet coverage dashboard can tell healthy from dead.
#
# Contract: docs/deployment/enrollment-and-heartbeat.md.
# Metadata only: host_id is a random UUID (not a hardware fingerprint), and the
# only counters sent are aggregate integers from the collector spool.
#
# Files under $AIM_CONFIG_DIR (default /etc/aim-collector):
#   config.json    ingest_url (written by install.sh)
#   host_id        device UUID, generated once here (0644)
#   enroll-token   admin-issued per-ring enrollment token (0640), optional
#   device-token   per-device token returned by /v1/enroll (0600)
set -uo pipefail

CONFIG_DIR="${AIM_CONFIG_DIR:-/etc/aim-collector}"
CONFIG_JSON="$CONFIG_DIR/config.json"
HOST_ID_FILE="$CONFIG_DIR/host_id"
ENROLL_TOKEN_FILE="$CONFIG_DIR/enroll-token"
DEVICE_TOKEN_FILE="$CONFIG_DIR/device-token"
COLLECTOR_VERSION="${AIM_COLLECTOR_VERSION:-0.1.0}"
RING="${AIM_RING:-pilot}"

log() { printf '[aim-heartbeat] %s\n' "$*"; }

[ -r "$CONFIG_JSON" ] || { log "no config at $CONFIG_JSON; skipping"; exit 0; }

INGEST_URL="${AIM_INGEST_URL:-$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ingest_url",""))' "$CONFIG_JSON" 2>/dev/null)}"
[ -n "$INGEST_URL" ] || { log "no ingest_url configured; skipping"; exit 0; }
INGEST_URL="${INGEST_URL%/}"

# --- device identity --------------------------------------------------------
if [ ! -s "$HOST_ID_FILE" ]; then
  umask 022
  python3 -c 'import uuid; print(uuid.uuid4())' > "$HOST_ID_FILE"
fi
HOST_ID="$(tr -d '[:space:]' < "$HOST_ID_FILE")"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"

os_string() {
  local id ver
  if [ -r /etc/os-release ]; then
    id="$(. /etc/os-release; echo "${ID:-linux}-${VERSION_ID:-}")"
  else
    id="linux"
  fi
  if grep -qi microsoft /proc/version 2>/dev/null; then echo "wsl-${id}"; else echo "$id"; fi
}
OS_STRING="$(os_string)"

# --- enroll once, if we have no device token yet ----------------------------
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
    log "enroll returned no device_token (already enrolled? admin re-issue needed); skipping"
    exit 0
  fi
  umask 077
  printf '%s' "$token" > "$DEVICE_TOKEN_FILE"
  chmod 0600 "$DEVICE_TOKEN_FILE"
  log "device enrolled; per-device token stored"
fi

# --- heartbeat --------------------------------------------------------------
DEVICE_TOKEN="$(tr -d '[:space:]' < "$DEVICE_TOKEN_FILE")"

# Best-effort aggregate counters from the collector spool (integers only).
spooled="$(find /home/*/.aim-collector/spool /root/.aim-collector/spool -type f 2>/dev/null | wc -l | tr -d ' ')"
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
