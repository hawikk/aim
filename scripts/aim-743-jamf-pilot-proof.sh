#!/usr/bin/env bash
# AIM-743 — pilot proof for Jamf macOS packaging (runs on Linux CI / agent host).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
pass() { printf 'PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); }

PROOF_ROOT="${AIM_PROOF_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/aim-743-proof.XXXXXX")}"
export AIM_VERSION=0.1.0-proof
export AIM_PKG_OUT="$PROOF_ROOT/dist"

echo "=== AIM-743 Jamf pilot proof ==="
echo "PROOF_ROOT=$PROOF_ROOT"

if ! bash deploy/macos/jamf/build-pkg.sh; then
  fail "build-pkg.sh exited non-zero"
  echo "RESULT: FAIL (build)"
  exit 1
fi
pass "build-pkg.sh stage"

STAGE="$AIM_PKG_OUT/stage"
for p in \
  "$STAGE/opt/aim-collector/aim_collector/__main__.py" \
  "$STAGE/opt/aim-collector/install.sh" \
  "$STAGE/opt/aim-collector/uninstall.sh" \
  "$STAGE/opt/aim-collector/aim-collector-scan.sh" \
  "$STAGE/opt/aim-collector/aim-collector-heartbeat.sh" \
  "$STAGE/opt/aim-collector/aim-collector-oob-health.sh" \
  "$STAGE/Library/LaunchDaemons/com.aimonitoring.collector-scan.plist" \
  "$STAGE/Library/LaunchDaemons/com.aimonitoring.collector-oob-health.plist" \
  "$STAGE/etc/aim-collector/version" \
  "$AIM_PKG_OUT/scripts/postinstall" \
  "$AIM_PKG_OUT/scripts/preuninstall" \
  "$AIM_PKG_OUT/stage-manifest.txt"
do
  if [ -e "$p" ]; then pass "stage has $(basename "$p")"
  else fail "missing $p"; fi
done

for label in com.aimonitoring.collector-scan com.aimonitoring.collector-oob-health; do
  if grep -q "<string>${label}</string>" "$STAGE/Library/LaunchDaemons/${label}.plist"; then
    pass "plist label $label"
  else
    fail "plist label $label"
  fi
done

PREFIX="$PROOF_ROOT/root"
mkdir -p "$PREFIX/Users/pilot/.claude"
export AIM_ROOT="$PREFIX"
export AIM_INGEST_URL="https://ingest.pilot.example"
export AIM_TOKEN="pilot-token-not-real"
export AIM_HASH_SALT="pilot-salt"
export AIM_ENROLL_TOKEN="pilot-enroll-not-real"
export AIM_USERS="pilot"
export AIM_NO_SCHEDULER=1
export AIM_VERSION="0.1.0-proof"

if bash deploy/macos/install.sh; then
  pass "install.sh under AIM_ROOT"
else
  fail "install.sh under AIM_ROOT"
fi

check_path() {
  local p="$1"
  if [ -e "$p" ]; then pass "installed $(echo "$p" | sed "s|$PREFIX||")"
  else fail "missing installed $p"; fi
}

check_path "$PREFIX/opt/aim-collector/aim_collector/__main__.py"
check_path "$PREFIX/opt/aim-collector/aim-collector-scan.sh"
check_path "$PREFIX/etc/aim-collector/config.json"
check_path "$PREFIX/etc/aim-collector/token"
check_path "$PREFIX/etc/aim-collector/enroll-token"
check_path "$PREFIX/etc/aim-collector/version"
check_path "$PREFIX/etc/aim-collector/enforcement.json"
check_path "$PREFIX/Library/LaunchDaemons/com.aimonitoring.collector-scan.plist"
check_path "$PREFIX/Library/LaunchDaemons/com.aimonitoring.collector-oob-health.plist"

ver="$(tr -d '[:space:]' < "$PREFIX/etc/aim-collector/version")"
if [ "$ver" = "0.1.0-proof" ]; then pass "version EA file = $ver"
else fail "version EA file got '$ver'"; fi

if grep -q 'ingest.pilot.example' "$PREFIX/etc/aim-collector/config.json"; then
  pass "config.json ingest_url"
else
  fail "config.json ingest_url"
fi

tok_mode="$(stat -c '%a' "$PREFIX/etc/aim-collector/token" 2>/dev/null || stat -f '%OLp' "$PREFIX/etc/aim-collector/token")"
if [ "$tok_mode" = "640" ] || [ "$tok_mode" = "0640" ]; then
  pass "token mode $tok_mode"
elif [ -n "$tok_mode" ] && [ $((8#$tok_mode & 8#004)) -eq 0 ] 2>/dev/null; then
  pass "token not world-readable (mode $tok_mode)"
else
  fail "token mode unexpected: $tok_mode"
fi

EA_OUT="$(
  VERSION_FILE="$PREFIX/etc/aim-collector/version"
  if [ -r "$VERSION_FILE" ]; then ver=$(tr -d '[:space:]' < "$VERSION_FILE"); else ver="Not Installed"; fi
  echo "<result>${ver}</result>"
)"
if [ "$EA_OUT" = "<result>0.1.0-proof</result>" ]; then pass "EA result envelope"
else fail "EA result envelope: $EA_OUT"; fi

MC="deploy/macos/jamf/profiles/com.aimonitoring.collector.mobileconfig"
if [ -f "$MC" ] && grep -q 'REPLACE_INGEST_URL' "$MC" && grep -q 'PayloadType' "$MC"; then
  pass "mobileconfig template"
else
  fail "mobileconfig template"
fi

export AIM_PURGE_STATE=1
if bash deploy/macos/uninstall.sh; then
  pass "uninstall.sh clean"
else
  fail "uninstall.sh residue"
fi

for p in \
  "$PREFIX/opt/aim-collector" \
  "$PREFIX/etc/aim-collector" \
  "$PREFIX/Library/LaunchDaemons/com.aimonitoring.collector-scan.plist" \
  "$PREFIX/Library/LaunchDaemons/com.aimonitoring.collector-oob-health.plist"
do
  if [ -e "$p" ]; then fail "residue remains: $p"
  else pass "no residue $(basename "$p")"; fi
done

echo
echo "=== summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
echo "Evidence tree retained at: $PROOF_ROOT"
exit 0
