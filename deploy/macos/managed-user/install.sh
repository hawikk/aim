#!/usr/bin/env bash
# AI Monitoring — per-user macOS managed installer (AIM-1170).
#
# Least privilege: LaunchAgent only. Refuses root (same policy as `aim join`).
# This is the artifact Jamf / Intune would call as the logged-in user.
# Live MDM fleet rollout remains AIM-28. The AIM-743 root LaunchDaemon
# package is deploy/macos/install.sh + deploy/macos/jamf/.
#
#   AIM_INGEST_URL=https://ingest.corp.example \
#   AIM_ENROLL_TOKEN_FILE=$HOME/aim-enroll-token \
#   ./deploy/macos/managed-user/install.sh
#
# Prefix / CI dry-run (no root, no launchctl, no network enroll):
#   AIM_HOME=/tmp/aim-proof AIM_NO_JOIN=1 ./deploy/macos/managed-user/install.sh
set -euo pipefail

log() { printf '[aim-macos-user] %s\n' "$*"; }
die() { printf '[aim-macos-user] ERROR: %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

current_euid() {
  if [ -n "${AIM_FAKE_EUID:-}" ]; then
    printf '%s\n' "$AIM_FAKE_EUID"
    return
  fi
  id -u
}

# Refuse root unless AIM_HOME remaps every write (CI / proof prefix).
if [ "$(current_euid)" -eq 0 ] && [ -z "${AIM_HOME:-}" ]; then
  die "refusing to install as root — run as the logged-in user (Jamf: Execute as user / Intune: signed-in user). Auto-start is the per-user LaunchAgent com.aimonitoring.aim-watch."
fi

[ -n "${AIM_INGEST_URL:-}" ] || die "AIM_INGEST_URL is required"

HOME_PREFIX="${AIM_HOME:-$HOME}"
MANAGED_DIR="${HOME_PREFIX}/Library/Application Support/AI-Monitoring/collector"
LAUNCH_AGENTS_DIR="${HOME_PREFIX}/Library/LaunchAgents"
LABEL="com.aimonitoring.aim-watch"

ENROLL_TOKEN="${AIM_ENROLL_TOKEN:-}"
if [ -z "$ENROLL_TOKEN" ] && [ -n "${AIM_ENROLL_TOKEN_FILE:-}" ]; then
  [ -r "$AIM_ENROLL_TOKEN_FILE" ] || die "AIM_ENROLL_TOKEN_FILE $AIM_ENROLL_TOKEN_FILE not readable"
  ENROLL_TOKEN="$(tr -d '[:space:]' < "$AIM_ENROLL_TOKEN_FILE")"
fi
EVENTS_TOKEN="${AIM_TOKEN:-}"
if [ -z "$EVENTS_TOKEN" ] && [ -n "${AIM_TOKEN_FILE:-}" ]; then
  [ -r "$AIM_TOKEN_FILE" ] || die "AIM_TOKEN_FILE $AIM_TOKEN_FILE not readable"
  EVENTS_TOKEN="$(tr -d '[:space:]' < "$AIM_TOKEN_FILE")"
fi
# Pilot convenience: a single token file can be the enroll token.
if [ -z "$ENROLL_TOKEN" ] && [ -n "$EVENTS_TOKEN" ]; then
  ENROLL_TOKEN="$EVENTS_TOKEN"
fi
[ -n "$ENROLL_TOKEN" ] || die "no enroll token: set AIM_ENROLL_TOKEN or AIM_ENROLL_TOKEN_FILE"

install -d -m 0700 "$MANAGED_DIR"
install -d -m 0755 "$LAUNCH_AGENTS_DIR"

TOKEN_PATH="$MANAGED_DIR/token"
ENROLL_PATH="$MANAGED_DIR/enroll-token"
CONFIG_PATH="$MANAGED_DIR/config.json"

umask 077
printf '%s' "$ENROLL_TOKEN" > "$ENROLL_PATH"
chmod 0600 "$ENROLL_PATH"
if [ -n "$EVENTS_TOKEN" ]; then
  printf '%s' "$EVENTS_TOKEN" > "$TOKEN_PATH"
  chmod 0600 "$TOKEN_PATH"
  TOKEN_FILE_JSON="$TOKEN_PATH"
else
  TOKEN_FILE_JSON="$TOKEN_PATH"
  : > "$TOKEN_PATH"
  chmod 0600 "$TOKEN_PATH"
fi

python3 - "$CONFIG_PATH" "$AIM_INGEST_URL" "$TOKEN_FILE_JSON" "${AIM_HASH_SALT:-}" <<'PY'
import json, sys
path, url, token_file, salt = sys.argv[1:5]
cfg = {
    "ingest_url": url,
    "token_file": token_file,
}
if salt:
    cfg["hash_salt"] = salt
open(path, "w", encoding="utf-8").write(json.dumps(cfg, indent=2) + "\n")
PY
chmod 0600 "$CONFIG_PATH"
log "managed config written to $CONFIG_PATH"

# Seed the same enforcement bundle `aim join` seeds (fail-open if missing).
ENFORCE_SRC="$REPO_ROOT/deploy/enforcement/enforcement.enforce.json"
if [ ! -f "$ENFORCE_SRC" ]; then
  ENFORCE_SRC="$REPO_ROOT/collectors/claude-code/aim_collector/default_enforcement.json"
fi
if [ -f "$ENFORCE_SRC" ]; then
  install -m 0600 "$ENFORCE_SRC" "$MANAGED_DIR/enforcement.json"
  log "enforcement bundle installed to $MANAGED_DIR/enforcement.json"
else
  log "WARNING: enforcement bundle not found — endpoint will fail-open to observe"
fi

aim_python() {
  # Prefer an installed `aim`, else the in-repo packaging tree.
  if [ -n "${AIM_PYTHON:-}" ]; then
    printf '%s\n' "$AIM_PYTHON"
    return
  fi
  printf '%s\n' "python3"
}

AIM_PY="$(aim_python)"
CLI_SRC="$REPO_ROOT/packaging/aim-cli/src"
export PYTHONPATH="${CLI_SRC}${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1
export AIM_LAUNCH_AGENTS_DIR="$LAUNCH_AGENTS_DIR"
export AIM_SERVICE_PLATFORM="${AIM_SERVICE_PLATFORM:-darwin}"

if [ -n "${AIM_NO_JOIN:-}" ]; then
  export AIM_SERVICE_NO_ACTIVATE=1
  "$AIM_PY" - <<'PY'
from aim import service
res = service.install()
print("auto-start:", res)
if not res.get("ok"):
    raise SystemExit(1)
PY
  log "LaunchAgent staged at $LAUNCH_AGENTS_DIR/${LABEL}.plist (AIM_NO_JOIN=1, not activated)"
else
  JOIN_ARGS=("$AIM_INGEST_URL" --token "$ENROLL_TOKEN")
  if [ -n "${AIM_RING:-}" ]; then
    JOIN_ARGS+=(--ring "$AIM_RING")
  fi
  if [ -n "${AIM_CA_BUNDLE:-}" ]; then
    JOIN_ARGS+=(--ca-bundle "$AIM_CA_BUNDLE")
  fi
  log "running aim join (enroll + hooks + LaunchAgent)"
  "$AIM_PY" -m aim join "${JOIN_ARGS[@]}"
fi

log "install complete"
log "user-level unit: ${LABEL}  (~/Library/LaunchAgents/${LABEL}.plist)"
log "managed config:  $CONFIG_PATH"
log "uninstall:       $SCRIPT_DIR/uninstall.sh"
