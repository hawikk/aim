#!/usr/bin/env bash
# AIM-745 — golden-image prepare (Linux / WSL template host).
#
# Installs the collector payload + scheduler at *image build time* without
# binding a device identity. Pair with seal-for-clone.sh before generalize
# / sysprep / AMI snapshot, then first-boot-enroll (or the normal heartbeat
# timer) auto-enrolls each clone.
#
#   sudo AIM_INGEST_URL=https://ingest.corp.example \
#        AIM_TOKEN_FILE=/run/secrets/aim-token \
#        AIM_ENROLL_TOKEN_FILE=/run/secrets/aim-enroll \
#        ./deploy/golden-image/prepare-image.sh
#
# Secrets: prefer file injection over env. Ring enroll tokens may be baked
# only when Security has approved a high-capacity, rotatable ring token
# (see docs/deployment/zero-touch-golden-image.md §Secrets).
#
# Environment (same as deploy/linux/install.sh, plus):
#   AIM_IMAGE_MODE=1   forced by this script (skips live user hook fan-out
#                      when no human users exist on the template)
#   AIM_SKIP_SEAL=1    leave seal for a later explicit step (default: seal)
#   AIM_ROOT           test prefix (CI / proof harness)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LINUX_DIR="$REPO_ROOT/deploy/linux"

log() { printf '[aim-prepare-image] %s\n' "$*"; }
die() { printf '[aim-prepare-image] ERROR: %s\n' "$*" >&2; exit 1; }

[ -x "$LINUX_DIR/install.sh" ] || [ -f "$LINUX_DIR/install.sh" ] || die "deploy/linux/install.sh not found"

# Map secret files → env expected by install.sh
if [ -z "${AIM_TOKEN:-}" ] && [ -n "${AIM_TOKEN_FILE:-}" ]; then
  [ -r "$AIM_TOKEN_FILE" ] || die "AIM_TOKEN_FILE not readable: $AIM_TOKEN_FILE"
  AIM_TOKEN="$(tr -d '[:space:]' < "$AIM_TOKEN_FILE")"
  export AIM_TOKEN
fi
if [ -z "${AIM_ENROLL_TOKEN:-}" ] && [ -n "${AIM_ENROLL_TOKEN_FILE:-}" ]; then
  [ -r "$AIM_ENROLL_TOKEN_FILE" ] || die "AIM_ENROLL_TOKEN_FILE not readable: $AIM_ENROLL_TOKEN_FILE"
  AIM_ENROLL_TOKEN="$(tr -d '[:space:]' < "$AIM_ENROLL_TOKEN_FILE")"
  export AIM_ENROLL_TOKEN
fi

[ -n "${AIM_INGEST_URL:-}" ] || die "AIM_INGEST_URL is required"
[ -n "${AIM_TOKEN:-}" ] || die "AIM_TOKEN or AIM_TOKEN_FILE is required for image-time install"

export AIM_IMAGE_MODE=1
# Template hosts often have no engineer accounts yet; install.sh still needs
# a non-empty user list only when registering hooks. Empty AIM_USERS skips.
export AIM_USERS="${AIM_USERS:-}"

# When imaging under AIM_ROOT (proof / chroot), skip live systemd.
if [ -n "${AIM_ROOT:-}" ]; then
  export AIM_NO_SCHEDULER="${AIM_NO_SCHEDULER:-1}"
fi

log "running deploy/linux/install.sh (image mode)"
# shellcheck disable=SC1091
bash "$LINUX_DIR/install.sh"

# Drop first-boot helper next to payload for clone boot paths that call it
# explicitly (cloud-init, MDM RunScript). Heartbeat timer remains the default.
ROOT="${AIM_ROOT:-}"
PAYLOAD_DIR="$ROOT/opt/aim-collector"
install -d -m 0755 "$PAYLOAD_DIR"
install -m 0755 "$SCRIPT_DIR/first-boot-enroll.sh" "$PAYLOAD_DIR/first-boot-enroll.sh"
install -m 0755 "$SCRIPT_DIR/seal-for-clone.sh" "$PAYLOAD_DIR/seal-for-clone.sh"
log "first-boot-enroll + seal helpers installed under $PAYLOAD_DIR"

# Marker: image prepared but not yet sealed (seal step clears device identity).
CONFIG_DIR="$ROOT/etc/aim-collector"
install -d -m 0755 "$CONFIG_DIR"
printf 'prepared\n' > "$CONFIG_DIR/image-state"
chmod 0644 "$CONFIG_DIR/image-state"

if [ "${AIM_SKIP_SEAL:-0}" = "1" ]; then
  log "AIM_SKIP_SEAL=1 — run seal-for-clone.sh before capturing the image"
else
  log "sealing identity for clone safety"
  AIM_ROOT="${AIM_ROOT:-}" bash "$SCRIPT_DIR/seal-for-clone.sh"
fi

log "prepare-image complete"
log "next: capture golden image / AMI / VHD, then deploy clones (auto-enroll on first heartbeat ≤5 min)"
