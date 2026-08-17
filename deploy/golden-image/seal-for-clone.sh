#!/usr/bin/env bash
# AIM-745 — strip per-device identity before generalizing a golden image.
#
# MUST run on the template host after prepare-image (or any install that may
# have enrolled during bake) and BEFORE sysprep / machine-id reset / AMI
# snapshot. Cloned devices that share host_id or device_token collapse into
# a single fleet row — this script is the fail-closed barrier.
#
# Safe to re-run. Preserves:
#   payload (/opt/aim-collector), managed config, ring secrets (token /
#   enroll-token), schedulers. Removes only identity + transient state.
#
#   sudo ./deploy/golden-image/seal-for-clone.sh
#   AIM_ROOT=/tmp/img ./deploy/golden-image/seal-for-clone.sh   # proof
set -euo pipefail

ROOT="${AIM_ROOT:-}"
CONFIG_DIR="$ROOT/etc/aim-collector"
PAYLOAD_DIR="$ROOT/opt/aim-collector"
WIN_STATE_HINT="$ROOT/ProgramData/AI-Monitoring/collector"  # rare wine/proof layout

log() { printf '[aim-seal] %s\n' "$*"; }

# --- machine-scoped identity (Linux managed path) ---------------------------
# host_id / device-token names match deploy/linux/aim-collector-heartbeat.sh
# (hyphenated). Python enroll-client uses underscores under AIM_STATE_DIR.
for f in host_id device-token device_token device_id last_heartbeat last-heartbeat; do
  if [ -e "$CONFIG_DIR/$f" ]; then
    rm -f "$CONFIG_DIR/$f"
    log "removed $CONFIG_DIR/$f"
  fi
done

# Machine state dir used by some install paths / future parity.
if [ -d "$CONFIG_DIR/state" ]; then
  rm -f "$CONFIG_DIR/state/host_id" \
        "$CONFIG_DIR/state/device_token" \
        "$CONFIG_DIR/state/device-token" \
        "$CONFIG_DIR/state/device_id" \
        "$CONFIG_DIR/state/last_heartbeat" 2>/dev/null || true
  # Leave empty state dir so permissions stay correct.
  log "cleared $CONFIG_DIR/state identity files"
fi

# --- per-user collector state -----------------------------------------------
# Keep spool/config shape? No — spools from the template are not the clone's.
# Wipe identity files; optionally wipe entire ~/.aim-collector when
# AIM_SEAL_PURGE_USER_STATE=1 (default: purge identity only, drop spools).
purge_user_state() {
  local home="$1"
  local dir="$home/.aim-collector"
  [ -d "$dir" ] || return 0
  if [ "${AIM_SEAL_PURGE_USER_STATE:-1}" = "1" ]; then
    rm -rf "$dir"
    log "purged $dir"
    return 0
  fi
  for f in host_id device_token device-token device_id last_heartbeat spool.jsonl; do
    rm -f "$dir/$f" 2>/dev/null || true
  done
  log "cleared identity under $dir"
}

if [ -n "$ROOT" ]; then
  # Prefixed proof layout: $ROOT/home/<user>
  if [ -d "$ROOT/home" ]; then
    for home in "$ROOT/home"/*; do
      [ -d "$home" ] || continue
      purge_user_state "$home"
    done
  fi
else
  while IFS=: read -r _u _x _uid _g _gecos home shell; do
    [ -n "${home:-}" ] || continue
    case "$home" in
      /home/*|/Users/*) purge_user_state "$home" ;;
    esac
  done < /etc/passwd
  # root home if present
  [ -d /root ] && purge_user_state /root
fi

# Windows proof layout under AIM_ROOT (cross-platform harness)
if [ -d "$WIN_STATE_HINT" ]; then
  rm -f "$WIN_STATE_HINT/state/host_id" \
        "$WIN_STATE_HINT/state/device_token" \
        "$WIN_STATE_HINT/state/device_id" \
        "$WIN_STATE_HINT/state/last_heartbeat" 2>/dev/null || true
  log "cleared Windows-style state under $WIN_STATE_HINT/state"
fi

# --- image markers ----------------------------------------------------------
if [ -d "$CONFIG_DIR" ] || [ -d "$PAYLOAD_DIR" ]; then
  install -d -m 0755 "$CONFIG_DIR"
  # first-boot-enroll consumes this flag; heartbeat path works without it.
  printf 'sealed\n' > "$CONFIG_DIR/image-state"
  chmod 0644 "$CONFIG_DIR/image-state"
  : > "$CONFIG_DIR/needs-enroll"
  chmod 0644 "$CONFIG_DIR/needs-enroll"
  log "image-state=sealed, needs-enroll marker set"
fi

# Fail-closed check: no host_id / device token may remain under managed paths.
leaked=0
for f in \
  "$CONFIG_DIR/host_id" \
  "$CONFIG_DIR/device-token" \
  "$CONFIG_DIR/device_token" \
  "$CONFIG_DIR/state/host_id" \
  "$CONFIG_DIR/state/device_token"
do
  if [ -e "$f" ]; then
    log "ERROR: identity still present: $f"
    leaked=1
  fi
done
if [ "$leaked" -ne 0 ]; then
  printf '[aim-seal] ERROR: seal incomplete — refuse to capture image\n' >&2
  exit 1
fi

log "seal complete — safe to generalize / snapshot"
exit 0
