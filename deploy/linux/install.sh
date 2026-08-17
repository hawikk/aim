#!/usr/bin/env bash
# AI Monitoring — collector installer for Linux / WSL (AIM-28).
#
# Idempotent, non-interactive. Run as root:
#   sudo AIM_INGEST_URL=https://ingest.corp.example \
#        AIM_TOKEN_FILE=/run/secrets/aim-token \
#        AIM_HASH_SALT=... \
#        ./install.sh
#
# Inputs (env):
#   AIM_INGEST_URL   (required) ingestion base URL
#   AIM_TOKEN        ingest bearer token (pilot: pre-shared per ring)
#   AIM_TOKEN_FILE   file to read the token from (alternative to AIM_TOKEN)
#   AIM_HASH_SALT    org-wide HMAC pseudonymization salt (must match ingestion)
#   AIM_USERS        space-separated users to register hooks for
#                    (default: SUDO_USER if set, else all human users uid>=1000)
#   AIM_ROOT         prefix every target path with this (testing only)
#   AIM_NO_SCHEDULER=1  skip systemd/cron setup (testing only)
#
# Layout installed:
#   /opt/aim-collector/aim_collector/   collector payload (root:root, 0755)
#   /etc/aim-collector/config.json      non-secret config (0644)
#   /etc/aim-collector/token            ingest token (0640 root:aim-collector)
#   systemd timer + service, or /etc/cron.d/aim-collector fallback
set -euo pipefail

ROOT="${AIM_ROOT:-}"
PAYLOAD_DIR="$ROOT/opt/aim-collector"
CONFIG_DIR="$ROOT/etc/aim-collector"
# AIM_PAYLOAD_SRC lets staged Intune WSL bridge packages supply the collector
# without a monorepo checkout on the target distro (AIM-742).
if [ -n "${AIM_PAYLOAD_SRC:-}" ]; then
  PKG_SRC="$AIM_PAYLOAD_SRC"
else
  PKG_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/collectors/claude-code/aim_collector"
fi

log() { printf '[aim-install] %s\n' "$*"; }
die() { printf '[aim-install] ERROR: %s\n' "$*" >&2; exit 1; }

[ -d "$PKG_SRC" ] || die "collector payload not found at $PKG_SRC"
[ -n "${AIM_INGEST_URL:-}" ] || die "AIM_INGEST_URL is required"

# --- token -----------------------------------------------------------------
TOKEN="${AIM_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -n "${AIM_TOKEN_FILE:-}" ]; then
  [ -r "$AIM_TOKEN_FILE" ] || die "AIM_TOKEN_FILE $AIM_TOKEN_FILE not readable"
  TOKEN="$(tr -d '[:space:]' < "$AIM_TOKEN_FILE")"
fi
[ -n "$TOKEN" ] || die "no token: set AIM_TOKEN or AIM_TOKEN_FILE"

if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
  die "must run as root (sudo)"
fi

# --- payload ---------------------------------------------------------------
install -d -m 0755 "$PAYLOAD_DIR"
rm -rf "$PAYLOAD_DIR/aim_collector"
cp -r "$PKG_SRC" "$PAYLOAD_DIR/aim_collector"
find "$PAYLOAD_DIR" -name __pycache__ -type d -prune -exec rm -rf {} +
chmod -R a+rX "$PAYLOAD_DIR"
log "payload installed to $PAYLOAD_DIR"

# --- config ----------------------------------------------------------------
install -d -m 0755 "$CONFIG_DIR"
umask 022
cat > "$CONFIG_DIR/config.json" <<EOF
{
  "ingest_url": "$AIM_INGEST_URL",
  "token_file": "/etc/aim-collector/token",
  "hash_salt": "${AIM_HASH_SALT:-}"
}
EOF
chmod 0644 "$CONFIG_DIR/config.json"

# Endpoint enforcement bundle (AIM-110 / AIM-296; delivery gap closed in AIM-440).
# Source of truth: policies/guardrail/v1/core.yaml → settings.enforcement.
# Without this file the collector fail-opens to observe and auditors see
# findings.decision=observe forever even when policy claims mode: enforce.
ENFORCE_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/deploy/enforcement/enforcement.enforce.json"
if [ ! -f "$ENFORCE_SRC" ]; then
  ENFORCE_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/collectors/claude-code/aim_collector/default_enforcement.json"
fi
if [ -f "$ENFORCE_SRC" ]; then
  install -m 0644 "$ENFORCE_SRC" "$CONFIG_DIR/enforcement.json"
  log "enforcement bundle installed to $CONFIG_DIR/enforcement.json (mode from bundle)"
else
  log "WARNING: enforcement bundle not found — endpoint will fail-open to observe"
fi

# Token readable by root and the aim-collector group only. Hooks run as the
# engineer and spool locally if the token is unreadable; the scheduled scan
# (root) drains spools with the token. Pilot posture, see
# docs/deployment/enrollment-and-heartbeat.md for the hardening path.
if [ -z "$ROOT" ]; then
  getent group aim-collector >/dev/null || groupadd --system aim-collector
  GROUP="aim-collector"
  install -m 0640 -o root -g "$GROUP" /dev/null "$CONFIG_DIR/token"
else
  GROUP="$(id -gn)"
  install -m 0640 /dev/null "$CONFIG_DIR/token"
fi
printf '%s' "$TOKEN" > "$CONFIG_DIR/token"
log "config written to $CONFIG_DIR (token mode 0640 root:$GROUP)"

# Optional per-ring enrollment token (AIM-28). When present, the device
# heartbeat helper enrolls once for a per-device token and starts heartbeating;
# without it the pilot falls back to event last-seen coverage.
if [ -n "${AIM_ENROLL_TOKEN:-}" ]; then
  if [ -z "$ROOT" ]; then
    install -m 0640 -o root -g "$GROUP" /dev/null "$CONFIG_DIR/enroll-token"
  else
    install -m 0640 /dev/null "$CONFIG_DIR/enroll-token"
  fi
  printf '%s' "$AIM_ENROLL_TOKEN" > "$CONFIG_DIR/enroll-token"
  log "enrollment token written (device will enroll + heartbeat)"
fi

# --- hook registration ------------------------------------------------------
target_users() {
  if [ -n "${AIM_USERS:-}" ]; then printf '%s\n' $AIM_USERS; return; fi
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then printf '%s\n' "$SUDO_USER"; return; fi
  awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd
}

export PYTHONPATH="$PAYLOAD_DIR"
export PYTHONDONTWRITEBYTECODE=1
for u in $(target_users); do
  if [ -n "$ROOT" ]; then
    home="$ROOT/home/$u"; mkdir -p "$home/.claude"
    AIM_CLAUDE_SETTINGS="$home/.claude/settings.json" \
      python3 -m aim_collector install >/dev/null
  else
    runuser -u "$u" -- env PYTHONPATH="$PAYLOAD_DIR" \
      python3 -m aim_collector install >/dev/null
  fi
  log "hooks registered for $u"
done

# --- optional fleet public key for signed config (AIM-639 / AIM-749) --------
# When AIM_CONFIG_PUBKEY_FILE is set, drop the Ed25519 public key so harden
# mode can verify managed config/enforcement envelopes. Ops retains the
# private key offline (scripts/sign_collector_bundle.py).
if [ -n "${AIM_CONFIG_PUBKEY_FILE:-}" ]; then
  [ -r "$AIM_CONFIG_PUBKEY_FILE" ] || die "AIM_CONFIG_PUBKEY_FILE not readable: $AIM_CONFIG_PUBKEY_FILE"
  install -m 0644 "$AIM_CONFIG_PUBKEY_FILE" "$CONFIG_DIR/config-pubkey.b64"
  log "config public key installed to $CONFIG_DIR/config-pubkey.b64"
fi
if [ "${AIM_HARDEN:-}" = "1" ] || [ "${AIM_HARDEN:-}" = "true" ]; then
  # Persist harden flag into managed config so hooks pick it up without env.
  python3 - "$CONFIG_DIR/config.json" <<'PY' || true
import json, sys
p = sys.argv[1]
try:
    cfg = json.load(open(p))
except Exception:
    cfg = {}
if not isinstance(cfg, dict):
    cfg = {}
cfg["harden"] = True
open(p, "w").write(json.dumps(cfg, indent=2) + "\n")
PY
  log "harden mode enabled in $CONFIG_DIR/config.json (AIM_HARDEN=1)"
fi

# --- scheduler: systemd timer, cron fallback --------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_WRAPPER="$SCRIPT_DIR/aim-collector-scan.sh"
install -m 0755 "$SCAN_WRAPPER" "$PAYLOAD_DIR/aim-collector-scan.sh"
install -m 0755 "$SCRIPT_DIR/aim-collector-heartbeat.sh" "$PAYLOAD_DIR/aim-collector-heartbeat.sh"
# AIM-639 / AIM-752: OOB host health independent of the agent user process.
install -m 0755 "$SCRIPT_DIR/aim-collector-oob-health.sh" "$PAYLOAD_DIR/aim-collector-oob-health.sh"
# Integrity package (signed config load path) for root OOB helper + harden.
if [ -d "$SCRIPT_DIR/../../collectors/integrity" ]; then
  rm -rf "$PAYLOAD_DIR/integrity"
  cp -r "$SCRIPT_DIR/../../collectors/integrity" "$PAYLOAD_DIR/integrity"
  find "$PAYLOAD_DIR/integrity" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
  # Drop test keys from the deployed payload (dev-only fixtures).
  rm -rf "$PAYLOAD_DIR/integrity/tests" "$PAYLOAD_DIR/integrity/testdata" 2>/dev/null || true
  log "integrity package installed to $PAYLOAD_DIR/integrity"
fi

if [ -z "${AIM_NO_SCHEDULER:-}" ]; then
  if [ -z "$ROOT" ] && command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
    install -m 0644 "$(dirname "$SCAN_WRAPPER")/systemd/aim-collector-scan.service" /etc/systemd/system/
    install -m 0644 "$(dirname "$SCAN_WRAPPER")/systemd/aim-collector-scan.timer" /etc/systemd/system/
    install -m 0644 "$(dirname "$SCAN_WRAPPER")/systemd/aim-collector-oob-health.service" /etc/systemd/system/
    install -m 0644 "$(dirname "$SCAN_WRAPPER")/systemd/aim-collector-oob-health.timer" /etc/systemd/system/
    # OOB health state dir (root-owned; agent user cannot rewrite without root).
    install -d -m 0755 /var/lib/aim
    systemctl daemon-reload
    systemctl enable --now aim-collector-scan.timer
    systemctl enable --now aim-collector-oob-health.timer
    log "systemd timers enabled (aim-collector-scan.timer + aim-collector-oob-health.timer)"
  else
    cat > "$ROOT/etc/cron.d/aim-collector" <<'EOF'
# AI Monitoring collector: transcript scan + spool flush every 5 minutes.
*/5 * * * * root /opt/aim-collector/aim-collector-scan.sh >/dev/null 2>&1
# AIM-639 OOB host health (independent of agent user process).
*/5 * * * * root /opt/aim-collector/aim-collector-oob-health.sh >/dev/null 2>&1
EOF
    chmod 0644 "$ROOT/etc/cron.d/aim-collector"
    log "cron fallback installed at /etc/cron.d/aim-collector (scan + oob-health)"
  fi
else
  log "scheduler setup skipped (AIM_NO_SCHEDULER=1)"
fi

log "install complete"
