#!/usr/bin/env bash
# install the aim-ci orphaned-job watchdog on a runner host.
#
# Usage (root, on aim-ci-runner / equivalent):
#   export GH_REPO=hawikk/aim
#   export RUNNER_NAME=aim-ci-gce
#   export GH_TOKEN=...   # classic PAT or fine-grained with Actions: Read
#   sudo -E ./deploy/runner/install-watchdog.sh
#
# Or from the monorepo checkout after scp:
#   sudo -E GH_TOKEN=... bash install-watchdog.sh
#
# Idempotent. Does not modify runner labels or aim-local-hawik (D-C2).
set -euo pipefail

log() { printf '[aim-watchdog-install] %s\n' "$*"; }
die() { printf '[aim-watchdog-install] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (sudo -E)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GH_REPO="${GH_REPO:-hawikk/aim}"
RUNNER_NAME="${RUNNER_NAME:-aim-ci-gce}"
ORPHAN_THRESHOLD_SEC="${ORPHAN_THRESHOLD_SEC:-600}"
COOLDOWN_SEC="${COOLDOWN_SEC:-1800}"
DRY_RUN="${DRY_RUN:-0}"
ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"
RUNNER_SERVICE="${RUNNER_SERVICE:-actions.runner.$(echo "$GH_REPO" | tr '/' '-').${RUNNER_NAME}.service}"

WATCHDOG_SRC="${SCRIPT_DIR}/watchdog-orphaned-job.sh"
UNIT_SRC="${SCRIPT_DIR}/systemd/aim-ci-runner-watchdog.service"
TIMER_SRC="${SCRIPT_DIR}/systemd/aim-ci-runner-watchdog.timer"

[ -f "$WATCHDOG_SRC" ] || die "missing $WATCHDOG_SRC"
[ -f "$UNIT_SRC" ] || die "missing $UNIT_SRC"
[ -f "$TIMER_SRC" ] || die "missing $TIMER_SRC"

install -d -m 0755 /etc/aim /var/lib/aim /usr/local/bin
install -m 0755 "$WATCHDOG_SRC" /usr/local/bin/aim-ci-runner-watchdog
install -m 0644 "$UNIT_SRC" /etc/systemd/system/aim-ci-runner-watchdog.service
install -m 0644 "$TIMER_SRC" /etc/systemd/system/aim-ci-runner-watchdog.timer

ENV_FILE=/etc/aim/runner-watchdog.env
if [ -f "$ENV_FILE" ]; then
  log "preserving existing $ENV_FILE (update keys if needed)"
  # Refresh non-secret config keys without clobbering GH_TOKEN.
  # shellcheck disable=SC1090
  set -a
  # shellcheck disable=SC1091
  . "$ENV_FILE" || true
  set +a
fi

# Prefer newly provided token; else keep prior env value.
TOKEN_LINE=""
if [ -n "${GH_TOKEN:-}" ]; then
  TOKEN_LINE="GH_TOKEN=${GH_TOKEN}"
elif [ -n "${GITHUB_TOKEN:-}" ]; then
  TOKEN_LINE="GH_TOKEN=${GITHUB_TOKEN}"
elif [ -f "$ENV_FILE" ]; then
  EXISTING_TOKEN="$(grep -E '^GH_TOKEN=' "$ENV_FILE" | head -1 | cut -d= -f2- || true)"
  if [ -n "$EXISTING_TOKEN" ]; then
    TOKEN_LINE="GH_TOKEN=${EXISTING_TOKEN}"
  fi
fi

umask 077
cat >"$ENV_FILE" <<EOF
# Managed by deploy/runner/install-watchdog.sh
GH_REPO=${GH_REPO}
RUNNER_NAME=${RUNNER_NAME}
RUNNER_SERVICE=${RUNNER_SERVICE}
ORPHAN_THRESHOLD_SEC=${ORPHAN_THRESHOLD_SEC}
COOLDOWN_SEC=${COOLDOWN_SEC}
STATE_FILE=/var/lib/aim/runner-watchdog-state.json
LOG_FILE=/var/lib/aim/runner-watchdog.log
DRY_RUN=${DRY_RUN}
ALERT_WEBHOOK_URL=${ALERT_WEBHOOK_URL}
${TOKEN_LINE}
EOF
chmod 0600 "$ENV_FILE"
log "wrote $ENV_FILE (mode 0600)"

if [ -z "$TOKEN_LINE" ]; then
  log "WARNING: no GH_TOKEN set — watchdog API calls will fail until token is added to $ENV_FILE"
fi

systemctl daemon-reload
systemctl enable --now aim-ci-runner-watchdog.timer
# Immediate first check (safe: only restarts after ORPHAN_THRESHOLD_SEC of orphan state)
systemctl start aim-ci-runner-watchdog.service || true

log "done. Timer: systemctl list-timers aim-ci-runner-watchdog.timer"
log "Logs:   journalctl -u aim-ci-runner-watchdog.service -n 50"
log "State:  cat /var/lib/aim/runner-watchdog-state.json"
log "Manual: systemctl start aim-ci-runner-watchdog.service"
