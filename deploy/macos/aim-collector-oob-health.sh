#!/usr/bin/env bash
# AI Monitoring — out-of-band host health signal for macOS.
# Runs as root via LaunchDaemon. POSTs /v1/heartbeat with source=oob_launchd.
set -uo pipefail

CONFIG_DIR="${AIM_CONFIG_DIR:-/etc/aim-collector}"
CONFIG_JSON="$CONFIG_DIR/config.json"
DEVICE_TOKEN_FILE="$CONFIG_DIR/device-token"
HOST_ID_FILE="$CONFIG_DIR/host_id"
OOB_DIR="${AIM_OOB_DIR:-/var/lib/aim}"
OOB_HEALTH_FILE="${AIM_OOB_HEALTH_FILE:-$OOB_DIR/oob-health.mtime}"
OOB_HEALTH_META="${AIM_OOB_HEALTH_META:-$OOB_DIR/oob-health.json}"
COLLECTOR_VERSION="${AIM_COLLECTOR_VERSION:-}"
if [ -z "$COLLECTOR_VERSION" ] && [ -r "$CONFIG_DIR/version" ]; then
  COLLECTOR_VERSION="$(tr -d '[:space:]' < "$CONFIG_DIR/version")"
fi
COLLECTOR_VERSION="${COLLECTOR_VERSION:-0.1.0}"
REPO_HINT="${AIM_REPO_ROOT:-}"

log() { printf '[aim-oob-health-macos] %s\n' "$*"; }

mkdir -p "$OOB_DIR"

write_via_python() {
  local host_id="${1:-}"
  if command -v python3 >/dev/null 2>&1; then
    AIM_OOB_HEALTH_FILE="$OOB_HEALTH_FILE" AIM_OOB_HEALTH_META="$OOB_HEALTH_META" \
    AIM_PAYLOAD_DIR="${AIM_PAYLOAD_DIR:-/opt/aim-collector}" \
    AIM_REPO_ROOT="${REPO_HINT:-}" \
      python3 -c '
import os, sys, time
from pathlib import Path
repo = os.environ.get("AIM_REPO_ROOT")
if repo:
    sys.path.insert(0, repo)
payload = os.environ.get("AIM_PAYLOAD_DIR", "/opt/aim-collector")
if payload and payload not in sys.path:
    sys.path.insert(0, payload)
host_id = sys.argv[1] or None
ver = sys.argv[2] or None
try:
    try:
        from collectors.integrity.oob_health import write_oob_heartbeat
    except Exception:
        from integrity.oob_health import write_oob_heartbeat  # type: ignore
    write_oob_heartbeat(host_id=host_id, collector_version=ver, source="oob_launchd")
except Exception:
    p = Path(os.environ["AIM_OOB_HEALTH_FILE"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"{time.time()}\n")
    meta = Path(os.environ["AIM_OOB_HEALTH_META"])
    meta.write_text(f\'{{"ts":{int(time.time())},"source":"oob_launchd"}}\n\')
' "$host_id" "$COLLECTOR_VERSION" 2>/dev/null && return 0
  fi
  date +%s >"$OOB_HEALTH_FILE"
  printf '{"ts":%s,"source":"oob_launchd"}\n' "$(date +%s)" >"$OOB_HEALTH_META"
}

HOST_ID=""
if [ -s "$HOST_ID_FILE" ]; then
  HOST_ID="$(tr -d '[:space:]' < "$HOST_ID_FILE")"
fi

export AIM_PAYLOAD_DIR="${AIM_PAYLOAD_DIR:-/opt/aim-collector}"
write_via_python "$HOST_ID"
log "wrote OOB health at $OOB_HEALTH_FILE"

if [ ! -r "$CONFIG_JSON" ] || [ ! -s "$DEVICE_TOKEN_FILE" ]; then
  log "no config/device-token; local OOB file only"
  exit 0
fi

INGEST_URL="${AIM_INGEST_URL:-$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ingest_url",""))' "$CONFIG_JSON" 2>/dev/null || true)}"
[ -n "$INGEST_URL" ] || { log "no ingest_url; local OOB file only"; exit 0; }
INGEST_URL="${INGEST_URL%/}"
DEVICE_TOKEN="$(tr -d '[:space:]' < "$DEVICE_TOKEN_FILE")"
[ -n "$HOST_ID" ] || HOST_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"

body="$(python3 -c 'import json,sys; print(json.dumps({"host_id":sys.argv[1],"collector_version":sys.argv[2],"os":"macos-oob","counters":{"source":"oob_launchd"},"config_version":"oob","source":"oob_launchd"}))' \
  "$HOST_ID" "$COLLECTOR_VERSION" 2>/dev/null)" || body=""

if [ -z "$body" ]; then
  log "could not build heartbeat body; local OOB file only"
  exit 0
fi

code="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST "$INGEST_URL/v1/heartbeat" \
  -H "Authorization: Bearer $DEVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$body" 2>/dev/null || echo 000)"
log "heartbeat HTTP $code (source=oob_launchd)"
exit 0
