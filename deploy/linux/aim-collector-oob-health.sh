#!/usr/bin/env bash
# AI Monitoring — out-of-band host health signal (AIM-639 / AIM-752).
#
# Runs as root via systemd timer, independent of any coding-agent process and
# of the per-user collector watch daemon. Touches a root-owned heartbeat file
# and, when a device token is present, POSTs /v1/heartbeat with
# source=oob_systemd so fleet coverage stays green even if the user agent
# kills its own collector tree.
#
# Contract: docs/security/adr-independence-from-agent-loop.md
set -uo pipefail

CONFIG_DIR="${AIM_CONFIG_DIR:-/etc/aim-collector}"
CONFIG_JSON="$CONFIG_DIR/config.json"
DEVICE_TOKEN_FILE="$CONFIG_DIR/device-token"
HOST_ID_FILE="$CONFIG_DIR/host_id"
OOB_DIR="${AIM_OOB_DIR:-/var/lib/aim}"
OOB_HEALTH_FILE="${AIM_OOB_HEALTH_FILE:-$OOB_DIR/oob-health.mtime}"
OOB_HEALTH_META="${AIM_OOB_HEALTH_META:-$OOB_DIR/oob-health.json}"
COLLECTOR_VERSION="${AIM_COLLECTOR_VERSION:-0.1.0}"
REPO_HINT="${AIM_REPO_ROOT:-}"

log() { printf '[aim-oob-health] %s\n' "$*"; }

mkdir -p "$OOB_DIR"

# Prefer the in-tree Python helper when available (package install / dev tree).
write_via_python() {
  local host_id="${1:-}"
  if command -v python3 >/dev/null 2>&1; then
    AIM_OOB_HEALTH_FILE="$OOB_HEALTH_FILE" AIM_OOB_HEALTH_META="$OOB_HEALTH_META" \
      python3 - "$host_id" "$COLLECTOR_VERSION" <<'PY' 2>/dev/null && return 0
import os, sys
from pathlib import Path

# Allow running from a checkout that has collectors/integrity on path
repo = os.environ.get("AIM_REPO_ROOT")
if repo:
    sys.path.insert(0, repo)
try:
    from collectors.integrity.oob_health import write_oob_heartbeat
except Exception:
    # Minimal fallback: just write the mtime file
    p = Path(os.environ["AIM_OOB_HEALTH_FILE"])
    p.parent.mkdir(parents=True, exist_ok=True)
    import time
    p.write_text(f"{time.time()}\n")
    sys.exit(0)

host_id = sys.argv[1] or None
ver = sys.argv[2] or None
write_oob_heartbeat(host_id=host_id, collector_version=ver, source="oob_systemd")
PY
  fi
  # Pure shell fallback
  date +%s >"$OOB_HEALTH_FILE"
  printf '{"ts":%s,"source":"oob_systemd"}\n' "$(date +%s)" >"$OOB_HEALTH_META"
}

HOST_ID=""
if [ -s "$HOST_ID_FILE" ]; then
  HOST_ID="$(tr -d '[:space:]' < "$HOST_ID_FILE")"
fi

if [ -n "$REPO_HINT" ]; then
  export AIM_REPO_ROOT="$REPO_HINT"
fi
write_via_python "$HOST_ID"
log "wrote OOB health at $OOB_HEALTH_FILE"

# Optional fleet heartbeat (same protocol as aim-collector-heartbeat.sh)
if [ ! -r "$CONFIG_JSON" ] || [ ! -s "$DEVICE_TOKEN_FILE" ]; then
  log "no config/device-token; local OOB file only"
  exit 0
fi

INGEST_URL="${AIM_INGEST_URL:-$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ingest_url",""))' "$CONFIG_JSON" 2>/dev/null || true)}"
[ -n "$INGEST_URL" ] || { log "no ingest_url; local OOB file only"; exit 0; }
INGEST_URL="${INGEST_URL%/}"
DEVICE_TOKEN="$(tr -d '[:space:]' < "$DEVICE_TOKEN_FILE")"
[ -n "$HOST_ID" ] || HOST_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"

body="$(python3 -c 'import json,sys; print(json.dumps({
  "host_id": sys.argv[1],
  "collector_version": sys.argv[2],
  "os": "linux-oob",
  "counters": {"source": "oob_systemd"},
  "config_version": "oob",
  "source": "oob_systemd",
}))' "$HOST_ID" "$COLLECTOR_VERSION" 2>/dev/null)" || body=""

if [ -z "$body" ]; then
  log "could not build heartbeat body; local OOB file only"
  exit 0
fi

code="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST "$INGEST_URL/v1/heartbeat" \
  -H "Authorization: Bearer $DEVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$body" 2>/dev/null || echo 000)"
log "heartbeat HTTP $code (source=oob_systemd)"
exit 0
