#!/usr/bin/env bash
# AI Monitoring — periodic scan wrapper for macOS.
# Runs `scan-once` + `flush` for every human user. Invoked by LaunchDaemon
# as root every 5 minutes.
set -uo pipefail

PAYLOAD_DIR="${AIM_PAYLOAD_DIR:-/opt/aim-collector}"
export PYTHONPATH="$PAYLOAD_DIR"
export PYTHONDONTWRITEBYTECODE=1

run_as_user() {
  local u="$1"
  shift
  if id "$u" >/dev/null 2>&1; then
    if command -v launchctl >/dev/null 2>&1; then
      local uid
      uid="$(id -u "$u" 2>/dev/null || true)"
      if [ -n "$uid" ] && [ "$uid" -gt 0 ] 2>/dev/null; then
        launchctl asuser "$uid" sudo -u "$u" env PYTHONPATH="$PAYLOAD_DIR" PYTHONDONTWRITEBYTECODE=1 "$@" \
          >/dev/null 2>&1 && return 0
      fi
    fi
    su -l "$u" -c "env PYTHONPATH='$PAYLOAD_DIR' PYTHONDONTWRITEBYTECODE=1 $*" \
      >/dev/null 2>&1 || true
  fi
}

scan_user() {
  local u="$1"
  run_as_user "$u" python3 -m aim_collector scan-once
  run_as_user "$u" python3 -m aim_collector flush
}

list_users() {
  if command -v dscl >/dev/null 2>&1; then
    dscl . -list /Users UniqueID 2>/dev/null \
      | awk '$2 >= 500 && $1 !~ /^_/ {print $1}'
    return
  fi
  awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null || true
}

users="$(list_users)"
if [ -d /var/root/.aim-collector ]; then
  users="$users root"
fi

for u in $users; do
  [ -n "$u" ] || continue
  scan_user "$u"
done

HEARTBEAT="$PAYLOAD_DIR/aim-collector-heartbeat.sh"
[ -x "$HEARTBEAT" ] && "$HEARTBEAT" >/dev/null 2>&1
exit 0
