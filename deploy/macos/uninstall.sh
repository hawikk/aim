#!/usr/bin/env bash
# AI Monitoring — collector uninstaller for macOS (Jamf).
# Idempotent. Removes launchd jobs, hooks, payload, and config; then verifies
# no residue remains and exits non-zero if anything is left behind.
#
#   sudo ./uninstall.sh
#   sudo AIM_PURGE_STATE=1 ./uninstall.sh
#   AIM_ROOT=/tmp/x ./uninstall.sh
set -uo pipefail

ROOT="${AIM_ROOT:-}"
PAYLOAD_DIR="$ROOT/opt/aim-collector"
CONFIG_DIR="$ROOT/etc/aim-collector"
LAUNCHD_DIR="$ROOT/Library/LaunchDaemons"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_SRC="$REPO_ROOT/collectors/claude-code/aim_collector"

log() { printf '[aim-uninstall-macos] %s\n' "$*"; }

for label in com.aimonitoring.collector-scan com.aimonitoring.collector-oob-health; do
  plist="$LAUNCHD_DIR/${label}.plist"
  if [ -z "$ROOT" ] && command -v launchctl >/dev/null 2>&1; then
    launchctl bootout "system/${label}" 2>/dev/null || true
    launchctl unload "$plist" 2>/dev/null || true
  fi
  rm -f "$plist"
done
log "LaunchDaemons removed (if present)"

if [ "${AIM_PURGE_STATE:-}" = "1" ]; then
  rm -rf "$ROOT/var/lib/aim"
  log "OOB health state purged (/var/lib/aim)"
fi

list_users() {
  if [ -n "${AIM_USERS:-}" ]; then
    # shellcheck disable=SC2086
    printf '%s\n' $AIM_USERS
    return
  fi
  if [ -z "$ROOT" ] && command -v dscl >/dev/null 2>&1; then
    dscl . -list /Users UniqueID 2>/dev/null \
      | awk '$2 >= 500 && $1 !~ /^_/ {print $1}'
    return
  fi
  awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null || true
}

users="$(list_users | sort -u)"
for u in $users; do
  [ -n "$u" ] || continue
  if [ -n "$ROOT" ]; then
    settings="$ROOT/Users/$u/.claude/settings.json"
    [ -f "$settings" ] || { log "no settings for $u, skipping"; continue; }
    AIM_CLAUDE_SETTINGS="$settings" \
      PYTHONPATH="$PKG_SRC/.." python3 -m aim_collector uninstall >/dev/null 2>&1 || true
  else
    home="$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    [ -n "$home" ] || home="$(getent passwd "$u" 2>/dev/null | cut -d: -f6 || true)"
    settings="${home}/.claude/settings.json"
    [ -f "$settings" ] || { log "no settings for $u, skipping"; continue; }
    su -l "$u" -c "env AIM_CLAUDE_SETTINGS='$settings' PYTHONPATH='$PKG_SRC/..' python3 -m aim_collector uninstall" \
      >/dev/null 2>&1 || true
  fi
  log "hooks removed for $u (if registered)"
done

rm -rf "$PAYLOAD_DIR"
rm -rf "$CONFIG_DIR"
log "payload and config removed"

if [ "${AIM_PURGE_STATE:-}" = "1" ]; then
  for u in $users; do
    if [ -n "$ROOT" ]; then
      home="$ROOT/Users/$u"
    else
      home="$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
      [ -n "$home" ] || home="$(getent passwd "$u" 2>/dev/null | cut -d: -f6 || true)"
    fi
    [ -n "$home" ] || continue
    rm -rf "${home}/.aim-collector"
  done
  log "per-user state purged"
fi

residue=0
paths=(
  "$PAYLOAD_DIR"
  "$CONFIG_DIR"
  "$LAUNCHD_DIR/com.aimonitoring.collector-scan.plist"
  "$LAUNCHD_DIR/com.aimonitoring.collector-oob-health.plist"
)
for p in "${paths[@]}"; do
  if [ -e "$p" ]; then log "RESIDUE: $p"; residue=1; fi
done
if [ "${AIM_PURGE_STATE:-}" = "1" ]; then
  for u in $users; do
    if [ -n "$ROOT" ]; then home="$ROOT/Users/$u"; else
      home="$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
      [ -n "$home" ] || home="$(getent passwd "$u" 2>/dev/null | cut -d: -f6 || true)"
    fi
    [ -e "${home}/.aim-collector" ] && { log "RESIDUE: ${home}/.aim-collector"; residue=1; }
  done
fi

if [ "$residue" -ne 0 ]; then
  log "FAILED: residue detected"
  exit 1
fi
log "uninstall complete, no residue"
