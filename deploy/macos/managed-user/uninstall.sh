#!/usr/bin/env bash
# AI Monitoring — per-user macOS uninstaller (AIM-1170).
# Idempotent. Refuses root (same as install) unless AIM_HOME remaps writes.
#
#   ./deploy/macos/managed-user/uninstall.sh
#   AIM_PURGE_STATE=1 ./deploy/macos/managed-user/uninstall.sh
#   AIM_HOME=/tmp/aim-proof ./deploy/macos/managed-user/uninstall.sh
set -uo pipefail

log() { printf '[aim-macos-user-uninstall] %s\n' "$*"; }
die() { printf '[aim-macos-user-uninstall] ERROR: %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

current_euid() {
  if [ -n "${AIM_FAKE_EUID:-}" ]; then
    printf '%s\n' "$AIM_FAKE_EUID"
    return
  fi
  id -u
}

if [ "$(current_euid)" -eq 0 ] && [ -z "${AIM_HOME:-}" ]; then
  die "refusing to uninstall as root — run as the same user that installed (LaunchAgent is per-user)"
fi

HOME_PREFIX="${AIM_HOME:-$HOME}"
MANAGED_DIR="${HOME_PREFIX}/Library/Application Support/AI-Monitoring/collector"
LAUNCH_AGENTS_DIR="${HOME_PREFIX}/Library/LaunchAgents"
LABEL="com.aimonitoring.aim-watch"
PLIST="$LAUNCH_AGENTS_DIR/${LABEL}.plist"

export PYTHONPATH="${REPO_ROOT}/packaging/aim-cli/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1
export AIM_LAUNCH_AGENTS_DIR="$LAUNCH_AGENTS_DIR"
export AIM_SERVICE_PLATFORM="${AIM_SERVICE_PLATFORM:-darwin}"
if [ -n "${AIM_HOME:-}" ] || [ -n "${AIM_NO_ACTIVATE:-}" ]; then
  export AIM_SERVICE_NO_ACTIVATE=1
fi

if python3 -c "from aim import service" >/dev/null 2>&1; then
  python3 - <<'PY' || true
from aim import service
for line in service.uninstall():
    print(line)
PY
  log "aim service uninstall invoked"
fi

if [ -z "${AIM_HOME:-}" ] && command -v launchctl >/dev/null 2>&1 && [ -f "$PLIST" ]; then
  launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null || true
  launchctl unload -w "$PLIST" 2>/dev/null || true
fi
rm -f "$PLIST"
log "LaunchAgent removed (if present): $PLIST"

rm -rf "$MANAGED_DIR"
# Parent vendor dir if now empty
rmdir "${HOME_PREFIX}/Library/Application Support/AI-Monitoring" 2>/dev/null || true
log "managed config removed: $MANAGED_DIR"

if [ "${AIM_PURGE_STATE:-}" = "1" ]; then
  rm -rf "${HOME_PREFIX}/.aim-collector" \
         "${HOME_PREFIX}/.aim-collector-cursor" \
         "${HOME_PREFIX}/.aim-collector-kilo" \
         "${HOME_PREFIX}/.aim-collector-kimi" \
         "${HOME_PREFIX}/.aim-collector-grok"
  log "per-user collector state purged"
fi

residue=0
for p in "$PLIST" "$MANAGED_DIR"; do
  if [ -e "$p" ]; then
    log "RESIDUE: $p"
    residue=1
  fi
done
if [ "$residue" -ne 0 ]; then
  log "FAILED: residue detected"
  exit 1
fi
log "uninstall complete, no residue"
exit 0
