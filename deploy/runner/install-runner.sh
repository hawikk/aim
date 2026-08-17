#!/usr/bin/env bash
# AIM-297 / Epic D: install a self-hosted GitHub Actions runner for PR security.
#
# This is the *standard* install path — not a snowflake box. Operators run it
# from a clean host that must NOT run the product compose stack (D-C2 hard path).
#
# Usage (root):
#   export GH_REPO=hawikk/aim                    # or hawikk/littlewiz
#   export RUNNER_LABELS=self-hosted,Linux,X64,aim-ci
#   export RUNNER_NAME=aim-ci-gce                # unique per host
#   # Registration token (short-lived):
#   export RUNNER_TOKEN=$(gh api -X POST "repos/${GH_REPO}/actions/runners/registration-token" --jq .token)
#   sudo -E ./deploy/runner/install-runner.sh
#
# Optional:
#   RUNNER_USER=gha-runner          (default)
#   RUNNER_HOME=/opt/actions-runner (default)
#   RUNNER_VERSION=2.323.0          (override pinned version)
#   AIM_RUNNER_ROLE=pr-ci           written to /etc/aim/runner-role
#
# Trust boundary (enforced by role file + labels, documented in
# docs/security/pr-security-runner.md):
#   - Untrusted PR code runs as RUNNER_USER, never as the stack owner.
#   - product_compose=forbidden — this host must not run stack-aim-*.
#   - Job-completed hook wipes $GITHUB_WORKSPACE between PRs.
set -euo pipefail

log() { printf '[aim-runner-install] %s\n' "$*"; }
die() { printf '[aim-runner-install] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (sudo -E)"

GH_REPO="${GH_REPO:-}"
RUNNER_TOKEN="${RUNNER_TOKEN:-}"
RUNNER_NAME="${RUNNER_NAME:-$(hostname -s)-runner}"
RUNNER_LABELS="${RUNNER_LABELS:-self-hosted,Linux,X64,aim-ci}"
RUNNER_USER="${RUNNER_USER:-gha-runner}"
RUNNER_HOME="${RUNNER_HOME:-/opt/actions-runner}"
RUNNER_VERSION="${RUNNER_VERSION:-2.323.0}"
AIM_RUNNER_ROLE="${AIM_RUNNER_ROLE:-pr-ci}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GH_ARCH=x64 ;;
  aarch64|arm64) GH_ARCH=arm64 ;;
  *) die "unsupported arch: $ARCH" ;;
esac

[ -n "$GH_REPO" ] || die "GH_REPO is required (e.g. hawikk/aim)"
[ -n "$RUNNER_TOKEN" ] || die "RUNNER_TOKEN is required (registration token)"

# --- OS user (distinct from stack owner) ---------------------------------
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  log "creating user $RUNNER_USER"
  useradd --system --create-home --home-dir "/home/${RUNNER_USER}" \
    --shell /bin/bash "$RUNNER_USER"
fi

# Docker group optional — needed only for image-build jobs; product compose
# is still forbidden via /etc/aim/runner-role.
if getent group docker >/dev/null 2>&1; then
  usermod -aG docker "$RUNNER_USER" || true
fi

# --- role marker (D-C2) --------------------------------------------------
install -d -m 0755 /etc/aim
cat > /etc/aim/runner-role <<EOF
# Written by deploy/runner/install-runner.sh (AIM-297)
role=${AIM_RUNNER_ROLE}
product_compose=forbidden
labels=${RUNNER_LABELS}
repo=${GH_REPO}
installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
chmod 0644 /etc/aim/runner-role
log "wrote /etc/aim/runner-role (product_compose=forbidden)"

# --- runner binary -------------------------------------------------------
install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0755 "$RUNNER_HOME"
TARBALL="actions-runner-linux-${GH_ARCH}-${RUNNER_VERSION}.tar.gz"
URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${TARBALL}"
if [ ! -x "${RUNNER_HOME}/run.sh" ]; then
  log "downloading runner ${RUNNER_VERSION} (${GH_ARCH})"
  tmp="$(mktemp -d)"
  curl -fsSL -o "${tmp}/${TARBALL}" "$URL"
  tar -xzf "${tmp}/${TARBALL}" -C "$RUNNER_HOME"
  chown -R "${RUNNER_USER}:${RUNNER_USER}" "$RUNNER_HOME"
  rm -rf "$tmp"
fi

# --- job-completed wipe (per-PR isolation residual cleanup) --------------
HOOK_DIR="/etc/aim/runner-hooks"
install -d -m 0755 "$HOOK_DIR"
cat > "${HOOK_DIR}/job-completed.sh" <<'HOOK'
#!/usr/bin/env bash
# Wipe the job workspace after every job so the next PR cannot read leftovers.
set -euo pipefail
if [ -n "${GITHUB_WORKSPACE:-}" ] && [ -d "${GITHUB_WORKSPACE}" ]; then
  find "${GITHUB_WORKSPACE}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
fi
HOOK
chmod 0755 "${HOOK_DIR}/job-completed.sh"

# Environment for the service: never expose product secrets into PR jobs.
ENV_FILE="/etc/aim/runner.env"
cat > "$ENV_FILE" <<EOF
ACTIONS_RUNNER_HOOK_JOB_COMPLETED=${HOOK_DIR}/job-completed.sh
# Intentionally empty of product DB/Redis/MinIO credentials.
EOF
chmod 0644 "$ENV_FILE"

# --- configure + install service ----------------------------------------
if [ ! -f "${RUNNER_HOME}/.runner" ]; then
  log "configuring runner ${RUNNER_NAME} for ${GH_REPO} labels=${RUNNER_LABELS}"
  sudo -u "$RUNNER_USER" env -i HOME="/home/${RUNNER_USER}" PATH="/usr/bin:/bin" \
    bash -lc "cd '${RUNNER_HOME}' && ./config.sh --unattended \
      --url 'https://github.com/${GH_REPO}' \
      --token '${RUNNER_TOKEN}' \
      --name '${RUNNER_NAME}' \
      --labels '${RUNNER_LABELS}' \
      --work _work \
      --replace"
fi

# systemd unit with EnvironmentFile for the wipe hook
UNIT="actions.runner.$(echo "$GH_REPO" | tr '/' '-').${RUNNER_NAME}.service"
if [ -x "${RUNNER_HOME}/svc.sh" ]; then
  # Official installer; then patch EnvironmentFile.
  cd "$RUNNER_HOME"
  ./svc.sh install "$RUNNER_USER" || true
fi

# Ensure EnvironmentFile is present on the unit (best-effort).
if systemctl cat "actions.runner."*".${RUNNER_NAME}.service" >/dev/null 2>&1; then
  UNIT_PATH="$(systemctl show -p FragmentPath --value "actions.runner."*".${RUNNER_NAME}.service" 2>/dev/null | head -1 || true)"
  if [ -n "${UNIT_PATH:-}" ] && [ -f "$UNIT_PATH" ]; then
    if ! grep -q 'EnvironmentFile=/etc/aim/runner.env' "$UNIT_PATH"; then
      # Drop-in is safer than rewriting the unit.
      drop="/etc/systemd/system/$(basename "$UNIT_PATH").d"
      install -d "$drop"
      cat > "${drop}/aim-hooks.conf" <<DROP
[Service]
EnvironmentFile=/etc/aim/runner.env
DROP
      systemctl daemon-reload
    fi
  fi
fi

systemctl enable --now "actions.runner."*".${RUNNER_NAME}.service" 2>/dev/null \
  || log "start the runner service manually: cd ${RUNNER_HOME} && sudo ./svc.sh start"

# --- health reporter (feeds D2 status screen) ---------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/health-report.sh" ]; then
  install -m 0755 "${SCRIPT_DIR}/health-report.sh" /usr/local/bin/aim-ci-runner-health
  cat > /etc/systemd/system/aim-ci-runner-health.service <<'UNIT'
[Unit]
Description=AIM CI runner health snapshot (AIM-297)
After=network-online.target

[Service]
Type=oneshot
Environment=AIM_CI_RUNNER_REPOS=%i
# Override via systemctl edit; default empty — set AIM_CI_RUNNER_REPOS in the timer env.
EnvironmentFile=-/etc/aim/runner-health.env
ExecStart=/usr/local/bin/aim-ci-runner-health
User=root
UNIT
  # Fix unit: %i is wrong without instance. Use a static unit.
  cat > /etc/systemd/system/aim-ci-runner-health.service <<UNIT
[Unit]
Description=AIM CI runner health snapshot (AIM-297)
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=-/etc/aim/runner-health.env
Environment=AIM_CI_RUNNER_REPOS=${GH_REPO}
ExecStart=/usr/local/bin/aim-ci-runner-health
UNIT
  cat > /etc/systemd/system/aim-ci-runner-health.timer <<'TIMER'
[Unit]
Description=Refresh AIM CI runner health every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s
Unit=aim-ci-runner-health.service

[Install]
WantedBy=timers.target
TIMER
  install -d -m 0755 /var/lib/aim
  cat > /etc/aim/runner-health.env <<EOF
AIM_CI_RUNNER_REPOS=${GH_REPO}
AIM_CI_RUNNER_STATUS_FILE=/var/lib/aim/ci-runner-status.json
# Set GH_TOKEN or rely on \`gh auth\` as root for API access.
EOF
  systemctl daemon-reload
  systemctl enable --now aim-ci-runner-health.timer
  systemctl start aim-ci-runner-health.service || true
  log "health reporter timer enabled → /var/lib/aim/ci-runner-status.json"
fi

# --- orphaned-job watchdog (AIM-406 / AIM-401 follow-up) -------------------
# Auto-restart when busy=true with 0 in_progress runs for >10 min.
# Requires GH_TOKEN in env (or already in /etc/aim/runner-watchdog.env) for
# GitHub API reads. Does not touch aim-local-hawik / D-C2 labels.
if [ -f "${SCRIPT_DIR}/install-watchdog.sh" ]; then
  log "installing orphaned-job watchdog (AIM-406)"
  # Preserve caller GH_TOKEN/GITHUB_TOKEN; install-watchdog is idempotent.
  env \
    GH_REPO="$GH_REPO" \
    RUNNER_NAME="$RUNNER_NAME" \
    GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}" \
    GITHUB_TOKEN="${GITHUB_TOKEN:-}" \
    bash "${SCRIPT_DIR}/install-watchdog.sh" \
    || log "watchdog install failed (non-fatal); re-run deploy/runner/install-watchdog.sh"
fi

log "done. Runner ${RUNNER_NAME} labels=${RUNNER_LABELS} for ${GH_REPO}"
log "verify: gh api repos/${GH_REPO}/actions/runners --jq '.runners[]|{name,status,labels:[.labels[].name]}'"
