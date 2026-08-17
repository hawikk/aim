#!/usr/bin/env bash
# — first-boot auto-enroll for sealed golden-image clones (Linux).
#
# Idempotent. Generates a fresh host_id if missing, then enrolls when a ring
# enroll-token is present and no device token exists. Prefer the normal
# heartbeat timer (`aim-collector-heartbeat.sh` every 5 min) — this script is
# the explicit first-boot / cloud-init / MDM RunScript entrypoint for
# operators who want enroll within seconds of first login, not ≤5 min.
#
#   sudo /opt/aim-collector/first-boot-enroll.sh
#   # or from repo during proof:
#   AIM_ROOT=/tmp/clone ./deploy/golden-image/first-boot-enroll.sh
#
# If secrets were NOT baked into the image, inject them first:
#   install -m 0640 -o root -g aim-collector /run/secrets/aim-token \
#     /etc/aim-collector/token
#   install -m 0640 -o root -g aim-collector /run/secrets/aim-enroll \
#     /etc/aim-collector/enroll-token
set -euo pipefail

ROOT="${AIM_ROOT:-}"
CONFIG_DIR="${AIM_CONFIG_DIR:-$ROOT/etc/aim-collector}"
PAYLOAD_DIR="$ROOT/opt/aim-collector"
HB="$PAYLOAD_DIR/aim-collector-heartbeat.sh"

log() { printf '[aim-first-boot] %s\n' "$*"; }

# Prefer installed helper; fall back to repo tree when running from checkout.
if [ ! -x "$HB" ] && [ ! -f "$HB" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -f "$SCRIPT_DIR/../linux/aim-collector-heartbeat.sh" ]; then
    HB="$SCRIPT_DIR/../linux/aim-collector-heartbeat.sh"
  fi
fi

if [ ! -f "$CONFIG_DIR/config.json" ]; then
  log "no managed config at $CONFIG_DIR/config.json — not an AIM image; exit 0"
  exit 0
fi

# Optional late secret injection (cloud-init / MDM drop dir).
SECRETS_DROP="${AIM_SECRETS_DROP:-$ROOT/var/lib/aim/first-boot-secrets}"
if [ -d "$SECRETS_DROP" ]; then
  install -d -m 0755 "$CONFIG_DIR"
  if [ -f "$SECRETS_DROP/token" ] && [ ! -s "$CONFIG_DIR/token" ]; then
    install -m 0640 "$SECRETS_DROP/token" "$CONFIG_DIR/token"
    log "injected token from $SECRETS_DROP"
  fi
  if [ -f "$SECRETS_DROP/enroll-token" ] && [ ! -s "$CONFIG_DIR/enroll-token" ]; then
    install -m 0640 "$SECRETS_DROP/enroll-token" "$CONFIG_DIR/enroll-token"
    log "injected enroll-token from $SECRETS_DROP"
  fi
  if [ -f "$SECRETS_DROP/config.json" ] && [ ! -s "$CONFIG_DIR/config.json" ]; then
    install -m 0644 "$SECRETS_DROP/config.json" "$CONFIG_DIR/config.json"
    log "injected config.json from $SECRETS_DROP"
  fi
fi

export AIM_CONFIG_DIR="$CONFIG_DIR"
if [ -n "${AIM_RING:-}" ]; then
  export AIM_RING
fi

if [ ! -f "$HB" ]; then
  log "ERROR: heartbeat helper not found at $HB"
  exit 1
fi

log "running enroll+heartbeat via $HB"
# Heartbeat script is intentionally best-effort (exits 0 on transient net).
bash "$HB"
rc=$?

if [ -s "$CONFIG_DIR/device-token" ] || [ -s "$CONFIG_DIR/device_token" ]; then
  rm -f "$CONFIG_DIR/needs-enroll"
  printf 'enrolled\n' > "$CONFIG_DIR/image-state"
  log "device token present — first-boot enroll OK"
else
  log "no device token yet (missing enroll-token, network, or transient error) — timer will retry"
fi

exit "$rc"
