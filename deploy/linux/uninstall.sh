#!/usr/bin/env bash
# AI Monitoring — collector uninstaller for Linux / WSL (AIM-28).
# Idempotent. Removes scheduler, hooks, payload, and config; then verifies
# no residue remains and exits non-zero if anything is left behind.
#
#   sudo ./uninstall.sh            # full uninstall, keeps per-user state
#   sudo AIM_PURGE_STATE=1 ./uninstall.sh   # also remove ~/.aim-collector
#   AIM_ROOT=/tmp/x ./uninstall.sh # testing prefix
set -uo pipefail

ROOT="${AIM_ROOT:-}"
PAYLOAD_DIR="$ROOT/opt/aim-collector"
CONFIG_DIR="$ROOT/etc/aim-collector"
PKG_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/collectors/claude-code/aim_collector"

log() { printf '[aim-uninstall] %s\n' "$*"; }

# --- scheduler ---------------------------------------------------------------
if [ -z "$ROOT" ] && command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  systemctl disable --now aim-collector-scan.timer 2>/dev/null
  systemctl disable --now aim-collector-oob-health.timer 2>/dev/null
  rm -f /etc/systemd/system/aim-collector-scan.timer \
        /etc/systemd/system/aim-collector-scan.service \
        /etc/systemd/system/aim-collector-oob-health.timer \
        /etc/systemd/system/aim-collector-oob-health.service
  systemctl daemon-reload
  log "systemd timers removed (scan + oob-health)"
fi
rm -f "$ROOT/etc/cron.d/aim-collector" && log "cron entry removed (if present)"
# OOB health state (optional purge with AIM_PURGE_STATE).
if [ "${AIM_PURGE_STATE:-}" = "1" ]; then
  rm -rf "$ROOT/var/lib/aim"
  log "OOB health state purged (/var/lib/aim)"
fi

# --- hook registration (per user) --------------------------------------------
if [ -n "${AIM_USERS:-}" ]; then
  users=$(printf '%s\n' $AIM_USERS)
else
  users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)
  [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ] && users="$users $SUDO_USER"
  users=$(printf '%s\n' $users | sort -u)
fi
for u in $users; do
  if [ -n "$ROOT" ]; then
    settings="$ROOT/home/$u/.claude/settings.json"
  else
    home=$(getent passwd "$u" | cut -d: -f6)
    settings="$home/.claude/settings.json"
  fi
  # Never create a settings file for a user who never had one.
  [ -f "$settings" ] || { log "no settings for $u, skipping"; continue; }
  if [ -n "$ROOT" ]; then
    AIM_CLAUDE_SETTINGS="$settings" \
      PYTHONPATH="$PKG_SRC/.." python3 -m aim_collector uninstall >/dev/null 2>&1
  else
    runuser -u "$u" -- env AIM_CLAUDE_SETTINGS="$settings" PYTHONPATH="$PKG_SRC/.." \
      python3 -m aim_collector uninstall >/dev/null 2>&1
  fi
  log "hooks removed for $u (if registered)"
done

# --- payload + config ----------------------------------------------------------
rm -rf "$PAYLOAD_DIR"
rm -rf "$CONFIG_DIR"
if [ -z "$ROOT" ] && getent group aim-collector >/dev/null; then
  groupdel aim-collector 2>/dev/null || true
fi
log "payload and config removed"

if [ "${AIM_PURGE_STATE:-}" = "1" ]; then
  for u in $users; do
    if [ -n "$ROOT" ]; then home="$ROOT/home/$u"; else home=$(getent passwd "$u" | cut -d: -f6); fi
    [ -n "$home" ] || continue
    rm -rf "${home}/.aim-collector"
  done
  log "per-user state purged"
fi

# --- residue verification -------------------------------------------------------
residue=0
paths=("$PAYLOAD_DIR" "$CONFIG_DIR" "$ROOT/etc/cron.d/aim-collector")
if [ -z "$ROOT" ]; then
  paths+=(/etc/systemd/system/aim-collector-scan.timer
          /etc/systemd/system/aim-collector-scan.service
          /etc/systemd/system/aim-collector-oob-health.timer
          /etc/systemd/system/aim-collector-oob-health.service)
fi
for p in "${paths[@]}"; do
  if [ -e "$p" ]; then log "RESIDUE: $p"; residue=1; fi
done
if [ "${AIM_PURGE_STATE:-}" = "1" ]; then
  for u in $users; do
    if [ -n "$ROOT" ]; then home="$ROOT/home/$u"; else home=$(getent passwd "$u" | cut -d: -f6); fi
    [ -e "${home}/.aim-collector" ] && { log "RESIDUE: ${home}/.aim-collector"; residue=1; }
  done
fi

if [ "$residue" -ne 0 ]; then
  log "FAILED: residue detected"
  exit 1
fi
log "uninstall complete, no residue"
