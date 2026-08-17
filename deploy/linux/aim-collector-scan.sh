#!/usr/bin/env bash
# AI Monitoring — periodic scan wrapper.
# Runs `scan-once` + `flush` for every human user (uid >= 1000, plus root if
# it has collector state). Invoked by systemd timer or cron as root.
set -uo pipefail

PAYLOAD_DIR="${AIM_PAYLOAD_DIR:-/opt/aim-collector}"
export PYTHONPATH="$PAYLOAD_DIR"

scan_user() {
  local u="$1"
  runuser -u "$u" -- env PYTHONPATH="$PAYLOAD_DIR" \
    python3 -m aim_collector scan-once >/dev/null 2>&1
  runuser -u "$u" -- env PYTHONPATH="$PAYLOAD_DIR" \
    python3 -m aim_collector flush >/dev/null 2>&1
}

users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)
[ -d /root/.aim-collector ] && users="$users root"

for u in $users; do
  scan_user "$u"
done

# Device-level enrollment + heartbeat, once per cycle, best-effort.
HEARTBEAT="$PAYLOAD_DIR/aim-collector-heartbeat.sh"
[ -x "$HEARTBEAT" ] && "$HEARTBEAT" >/dev/null 2>&1
exit 0
