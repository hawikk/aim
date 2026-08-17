#!/usr/bin/env bash
# — dry-run proof for the per-user macOS managed installer.
# Runs on Linux CI / agent hosts. No root, no launchctl, no network enroll.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
pass() { printf 'PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); }

PROOF_ROOT="${AIM_PROOF_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/aim-1170-proof.XXXXXX")}"
echo "=== macOS managed-user proof ==="
echo "PROOF_ROOT=$PROOF_ROOT"
echo "euid=$(id -u) (must not be 0 for the successful dry-run)"

if [ "$(id -u)" -eq 0 ]; then
  fail "proof runner is root — cannot demonstrate a non-root install"
  echo "RESULT: FAIL"
  exit 1
fi
pass "proof runner is non-root (uid $(id -u))"

for f in \
  deploy/macos/managed-user/install.sh \
  deploy/macos/managed-user/uninstall.sh
do
  if bash -n "$f"; then
    pass "bash -n $f"
  else
    fail "bash -n $f"
  fi
done

# Refuse-root: fake euid 0 without AIM_HOME must fail.
set +e
OUT="$(AIM_FAKE_EUID=0 AIM_INGEST_URL=https://ingest.example \
  AIM_ENROLL_TOKEN=tok \
  bash deploy/macos/managed-user/install.sh 2>&1)"
RC=$?
set -e
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -qi 'refusing to install as root'; then
  pass "install.sh refuses root (AIM_FAKE_EUID=0)"
else
  fail "install.sh did not refuse root (rc=$RC)"
  printf '%s\n' "$OUT"
fi

set +e
OUT="$(AIM_FAKE_EUID=0 bash deploy/macos/managed-user/uninstall.sh 2>&1)"
RC=$?
set -e
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -qi 'refusing to uninstall as root'; then
  pass "uninstall.sh refuses root"
else
  fail "uninstall.sh did not refuse root (rc=$RC)"
fi

# Prefix dry-run: writes user Application Support + LaunchAgent, never daemons.
PREFIX="$PROOF_ROOT/home"
export AIM_HOME="$PREFIX"
export AIM_INGEST_URL="https://ingest.pilot.example"
export AIM_ENROLL_TOKEN="pilot-enroll-not-real"
export AIM_TOKEN="pilot-events-not-real"
export AIM_HASH_SALT="pilot-salt"
export AIM_NO_JOIN=1
export AIM_SERVICE_NO_ACTIVATE=1

if bash deploy/macos/managed-user/install.sh; then
  pass "install.sh under AIM_HOME (no root, no join)"
else
  fail "install.sh under AIM_HOME"
fi

MANAGED="$PREFIX/Library/Application Support/AI-Monitoring/collector"
PLIST="$PREFIX/Library/LaunchAgents/com.aimonitoring.aim-watch.plist"

for p in \
  "$MANAGED/config.json" \
  "$MANAGED/token" \
  "$MANAGED/enroll-token" \
  "$MANAGED/enforcement.json" \
  "$PLIST"
do
  if [ -e "$p" ]; then
    pass "installed ${p#"$PREFIX"}"
  else
    fail "missing $p"
  fi
done

if grep -q '"ingest_url": "https://ingest.pilot.example"' "$MANAGED/config.json"; then
  pass "config.json ingest_url"
else
  fail "config.json missing ingest_url"
fi

if grep -q 'com.aimonitoring.aim-watch' "$PLIST" \
  && grep -q 'aim' "$PLIST" \
  && grep -q 'watch' "$PLIST"; then
  pass "LaunchAgent plist is com.aimonitoring.aim-watch → aim watch"
else
  fail "LaunchAgent plist missing label or watch command"
fi

# Must not have written system/root surfaces under the prefix.
if [ ! -e "$PREFIX/Library/LaunchDaemons" ] && [ ! -e "$PREFIX/etc/aim-collector" ] \
   && [ ! -e "$PREFIX/opt/aim-collector" ]; then
  pass "no LaunchDaemon / /etc / /opt payload under AIM_HOME"
else
  fail "system-scoped paths appeared under AIM_HOME"
fi

# Scripts themselves must not install LaunchDaemons (comments may mention them).
if grep -E '^[^#]*LaunchDaemons' deploy/macos/managed-user/install.sh \
     deploy/macos/managed-user/uninstall.sh >/dev/null; then
  fail "managed-user scripts install LaunchDaemons"
else
  pass "managed-user scripts do not install LaunchDaemons"
fi

# Collector Darwin candidates (stdlib unittest, no extra deps).
for pkg_dir in \
  collectors/claude-code \
  collectors/cursor \
  collectors/kilo-code \
  collectors/kimi-code \
  collectors/grok-build
do
  if (cd "$pkg_dir" && python3 -m unittest discover -s tests -p 'test_config.py' -q); then
    pass "unittest $pkg_dir/tests/test_config.py"
  else
    fail "unittest $pkg_dir/tests/test_config.py"
  fi
done

python3 - <<'PY'
import importlib.util
from pathlib import Path
p = Path("collectors/managed-config/paths.py")
spec = importlib.util.spec_from_file_location("aim_managed_paths", p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert mod.DARWIN_MANAGED_DIR != mod.LINUX_MANAGED_DIR
cands = [str(x) for x in mod.managed_file_candidates("config.json", plat="darwin")]
assert cands[0] == mod.DARWIN_MANAGED_DIR + "/config.json", cands
assert cands[-1] == mod.LINUX_MANAGED_DIR + "/config.json", cands
print("shared managed-config oracle ok")
PY
pass "shared Darwin managed-config oracle"

# Uninstall residue check
if bash deploy/macos/managed-user/uninstall.sh; then
  pass "uninstall.sh under AIM_HOME"
else
  fail "uninstall.sh under AIM_HOME"
fi
if [ ! -e "$MANAGED" ] && [ ! -e "$PLIST" ]; then
  pass "uninstall left no residue"
else
  fail "uninstall residue remains"
fi

echo
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
exit 0
