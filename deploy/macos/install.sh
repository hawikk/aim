#!/usr/bin/env bash
# AI Monitoring — collector installer for macOS (AIM-743 / Jamf MDM).
#
# Idempotent, non-interactive. Run as root (Jamf policy / pkg postinstall):
#   sudo AIM_INGEST_URL=https://ingest.corp.example \
#        AIM_TOKEN_FILE=/var/root/aim-token \
#        AIM_HASH_SALT=... \
#        ./install.sh
#
# Inputs (env):
#   AIM_INGEST_URL   (required) ingestion base URL
#   AIM_TOKEN        ingest bearer token (pilot: pre-shared per ring)
#   AIM_TOKEN_FILE   file to read the token from (alternative to AIM_TOKEN)
#   AIM_ENROLL_TOKEN optional per-ring enrollment token (fleet coverage)
#   AIM_HASH_SALT    org-wide HMAC pseudonymization salt
#   AIM_USERS        space-separated users to register hooks for
#   AIM_ROOT         prefix every target path (testing / pilot proof only)
#   AIM_NO_SCHEDULER=1  skip launchd load (testing only)
#   AIM_VERSION      package version written for Jamf EA detection (default 0.1.0)
#   AIM_HARDEN=1     enable signed-config harden mode in managed config
#   AIM_CONFIG_PUBKEY_FILE  Ed25519 public key file for harden mode
#
# Layout installed:
#   /opt/aim-collector/                 collector payload + wrappers
#   /etc/aim-collector/config.json      non-secret config (0644)
#   /etc/aim-collector/token            ingest token (0640 root:wheel)
#   /etc/aim-collector/version          detection string for Jamf EA
#   /Library/LaunchDaemons/
#     com.aimonitoring.collector-scan.plist
#     com.aimonitoring.collector-oob-health.plist
set -euo pipefail

ROOT="${AIM_ROOT:-}"
PAYLOAD_DIR="$ROOT/opt/aim-collector"
CONFIG_DIR="$ROOT/etc/aim-collector"
LAUNCHD_DIR="$ROOT/Library/LaunchDaemons"
VERSION="${AIM_VERSION:-0.1.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PKG_SRC="$REPO_ROOT/collectors/claude-code/aim_collector"

log() { printf '[aim-install-macos] %s\n' "$*"; }
die() { printf '[aim-install-macos] ERROR: %s\n' "$*" >&2; exit 1; }

[ -d "$PKG_SRC" ] || die "collector payload not found at $PKG_SRC"
[ -n "${AIM_INGEST_URL:-}" ] || die "AIM_INGEST_URL is required"

TOKEN="${AIM_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -n "${AIM_TOKEN_FILE:-}" ]; then
  [ -r "$AIM_TOKEN_FILE" ] || die "AIM_TOKEN_FILE $AIM_TOKEN_FILE not readable"
  TOKEN="$(tr -d '[:space:]' < "$AIM_TOKEN_FILE")"
fi
[ -n "$TOKEN" ] || die "no token: set AIM_TOKEN or AIM_TOKEN_FILE"

if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
  die "must run as root (sudo / Jamf)"
fi

install -d -m 0755 "$PAYLOAD_DIR"
rm -rf "$PAYLOAD_DIR/aim_collector"
cp -r "$PKG_SRC" "$PAYLOAD_DIR/aim_collector"
find "$PAYLOAD_DIR" -name __pycache__ -type d -prune -exec rm -rf {} +
chmod -R a+rX "$PAYLOAD_DIR"
log "payload installed to $PAYLOAD_DIR"

if [ -d "$REPO_ROOT/collectors/integrity" ]; then
  rm -rf "$PAYLOAD_DIR/integrity"
  cp -r "$REPO_ROOT/collectors/integrity" "$PAYLOAD_DIR/integrity"
  find "$PAYLOAD_DIR/integrity" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
  rm -rf "$PAYLOAD_DIR/integrity/tests" "$PAYLOAD_DIR/integrity/testdata" 2>/dev/null || true
  log "integrity package installed to $PAYLOAD_DIR/integrity"
fi

install -m 0755 "$SCRIPT_DIR/aim-collector-scan.sh" "$PAYLOAD_DIR/aim-collector-scan.sh"
install -m 0755 "$SCRIPT_DIR/aim-collector-heartbeat.sh" "$PAYLOAD_DIR/aim-collector-heartbeat.sh"
install -m 0755 "$SCRIPT_DIR/aim-collector-oob-health.sh" "$PAYLOAD_DIR/aim-collector-oob-health.sh"
install -m 0755 "$SCRIPT_DIR/install.sh" "$PAYLOAD_DIR/install.sh"
install -m 0755 "$SCRIPT_DIR/uninstall.sh" "$PAYLOAD_DIR/uninstall.sh"

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

ENFORCE_SRC="$REPO_ROOT/deploy/enforcement/enforcement.enforce.json"
if [ ! -f "$ENFORCE_SRC" ]; then
  ENFORCE_SRC="$REPO_ROOT/collectors/claude-code/aim_collector/default_enforcement.json"
fi
if [ -f "$ENFORCE_SRC" ]; then
  install -m 0644 "$ENFORCE_SRC" "$CONFIG_DIR/enforcement.json"
  log "enforcement bundle installed to $CONFIG_DIR/enforcement.json"
else
  log "WARNING: enforcement bundle not found — endpoint will fail-open to observe"
fi

install -m 0640 /dev/null "$CONFIG_DIR/token"
printf '%s' "$TOKEN" > "$CONFIG_DIR/token"
chmod 0640 "$CONFIG_DIR/token"
log "config written to $CONFIG_DIR (token mode 0640)"

if [ -n "${AIM_ENROLL_TOKEN:-}" ]; then
  install -m 0640 /dev/null "$CONFIG_DIR/enroll-token"
  printf '%s' "$AIM_ENROLL_TOKEN" > "$CONFIG_DIR/enroll-token"
  chmod 0640 "$CONFIG_DIR/enroll-token"
  log "enrollment token written (device will enroll + heartbeat)"
fi

printf '%s\n' "$VERSION" > "$CONFIG_DIR/version"
chmod 0644 "$CONFIG_DIR/version"
log "version $VERSION written for EA detection"

if [ -n "${AIM_CONFIG_PUBKEY_FILE:-}" ]; then
  [ -r "$AIM_CONFIG_PUBKEY_FILE" ] || die "AIM_CONFIG_PUBKEY_FILE not readable: $AIM_CONFIG_PUBKEY_FILE"
  install -m 0644 "$AIM_CONFIG_PUBKEY_FILE" "$CONFIG_DIR/config-pubkey.b64"
  log "config public key installed to $CONFIG_DIR/config-pubkey.b64"
fi
if [ "${AIM_HARDEN:-}" = "1" ] || [ "${AIM_HARDEN:-}" = "true" ]; then
  python3 -c '
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
' "$CONFIG_DIR/config.json" || true
  log "harden mode enabled in $CONFIG_DIR/config.json (AIM_HARDEN=1)"
fi

target_users() {
  if [ -n "${AIM_USERS:-}" ]; then
    # shellcheck disable=SC2086
    printf '%s\n' $AIM_USERS
    return
  fi
  if [ -z "$ROOT" ] && command -v scutil >/dev/null 2>&1; then
    console_user="$(stat -f '%Su' /dev/console 2>/dev/null || true)"
    if [ -n "$console_user" ] && [ "$console_user" != "root" ] && [ "$console_user" != "loginwindow" ]; then
      printf '%s\n' "$console_user"
      return
    fi
  fi
  if [ -z "$ROOT" ] && command -v dscl >/dev/null 2>&1; then
    dscl . -list /Users UniqueID 2>/dev/null \
      | awk '$2 >= 500 && $1 !~ /^_/ {print $1}'
    return
  fi
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    printf '%s\n' "$SUDO_USER"
    return
  fi
  awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null || true
}

export PYTHONPATH="$PAYLOAD_DIR"
export PYTHONDONTWRITEBYTECODE=1
for u in $(target_users); do
  [ -n "$u" ] || continue
  if [ -n "$ROOT" ]; then
    home="$ROOT/Users/$u"
    mkdir -p "$home/.claude"
    AIM_CLAUDE_SETTINGS="$home/.claude/settings.json" \
      python3 -m aim_collector install >/dev/null 2>&1 || true
  else
    home="$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    if [ -z "$home" ]; then
      home="$(getent passwd "$u" 2>/dev/null | cut -d: -f6 || true)"
    fi
    [ -n "$home" ] || { log "skip $u: no home"; continue; }
    if id "$u" >/dev/null 2>&1; then
      su -l "$u" -c "env PYTHONPATH='$PAYLOAD_DIR' PYTHONDONTWRITEBYTECODE=1 python3 -m aim_collector install" \
        >/dev/null 2>&1 || true
    fi
  fi
  log "hooks registered for $u (best-effort)"
done

install -d -m 0755 "$LAUNCHD_DIR"
for label in com.aimonitoring.collector-scan com.aimonitoring.collector-oob-health; do
  src="$SCRIPT_DIR/launchd/${label}.plist"
  [ -f "$src" ] || die "missing LaunchDaemon template $src"
  if [ -n "$ROOT" ]; then
    sed "s|/opt/aim-collector|${PAYLOAD_DIR}|g" "$src" > "$LAUNCHD_DIR/${label}.plist"
  else
    install -m 0644 "$src" "$LAUNCHD_DIR/${label}.plist"
  fi
  chmod 0644 "$LAUNCHD_DIR/${label}.plist"
done
log "LaunchDaemon plists installed under $LAUNCHD_DIR"

if [ -z "${AIM_NO_SCHEDULER:-}" ] && [ -z "$ROOT" ] && command -v launchctl >/dev/null 2>&1; then
  for label in com.aimonitoring.collector-scan com.aimonitoring.collector-oob-health; do
    plist="$LAUNCHD_DIR/${label}.plist"
    if launchctl bootout "system/${label}" 2>/dev/null; then
      :
    else
      launchctl unload "$plist" 2>/dev/null || true
    fi
    if launchctl bootstrap system "$plist" 2>/dev/null; then
      launchctl enable "system/${label}" 2>/dev/null || true
      launchctl kickstart -k "system/${label}" 2>/dev/null || true
      log "launchd loaded: $label (bootstrap)"
    else
      launchctl load -w "$plist" 2>/dev/null || log "WARNING: launchctl load failed for $label"
      log "launchd loaded: $label (load -w)"
    fi
  done
  install -d -m 0755 /var/lib/aim
else
  log "launchd activation skipped (AIM_NO_SCHEDULER or AIM_ROOT or no launchctl)"
fi

log "install complete (version $VERSION)"
