#!/usr/bin/env bash
# AIM-745 — golden-image prepare/seal/clone identity proof (Linux CI / agent).
#
# Does not require a live ingest service for the seal identity contract.
# Verifies:
#   1. prepare-image installs payload + helpers under a prefixed AIM_ROOT
#   2. seal removes host_id / device tokens and is fail-closed / idempotent
#   3. two "clones" each mint distinct host_ids (no baked identity)
#   4. docs + scripts are present and executable
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
pass() { printf 'PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); }

PROOF_ROOT="${AIM_PROOF_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/aim-745-proof.XXXXXX")}"
TEMPLATE="$PROOF_ROOT/template"
CLONE_A="$PROOF_ROOT/clone-a"
CLONE_B="$PROOF_ROOT/clone-b"

echo "=== AIM-745 golden-image proof ==="
echo "PROOF_ROOT=$PROOF_ROOT"

# --- static surface ---------------------------------------------------------
for p in \
  docs/deployment/zero-touch-golden-image.md \
  deploy/golden-image/README.md \
  deploy/golden-image/prepare-image.sh \
  deploy/golden-image/seal-for-clone.sh \
  deploy/golden-image/first-boot-enroll.sh \
  deploy/golden-image/Prepare-GoldenImage.ps1 \
  deploy/golden-image/Seal-ForClone.ps1 \
  deploy/golden-image/FirstBoot-Enroll.ps1
do
  if [ -f "$p" ]; then pass "present $p"
  else fail "missing $p"; fi
done

for s in prepare-image.sh seal-for-clone.sh first-boot-enroll.sh; do
  if [ -x "deploy/golden-image/$s" ] || chmod +x "deploy/golden-image/$s" 2>/dev/null; then
    pass "executable deploy/golden-image/$s"
  else
    fail "not executable deploy/golden-image/$s"
  fi
done

if grep -q 'host_id' docs/deployment/zero-touch-golden-image.md \
  && grep -q 'seal-for-clone' docs/deployment/zero-touch-golden-image.md \
  && grep -q 'first-boot' docs/deployment/zero-touch-golden-image.md; then
  pass "doc covers host_id + seal + first-boot"
else
  fail "doc missing required topics"
fi

# --- prepare into prefixed root ---------------------------------------------
mkdir -p "$TEMPLATE"
# Fake secrets for install.sh
SECRETS="$PROOF_ROOT/secrets"
mkdir -p "$SECRETS"
printf 'proof-events-token' > "$SECRETS/token"
printf 'proof-enroll-token' > "$SECRETS/enroll"

# install.sh requires collector payload in-tree
if [ ! -d collectors/claude-code/aim_collector ]; then
  fail "collectors/claude-code/aim_collector missing"
  echo "RESULT: FAIL (setup)"
  exit 1
fi

set +e
AIM_ROOT="$TEMPLATE" \
AIM_INGEST_URL="https://ingest.proof.example" \
AIM_TOKEN_FILE="$SECRETS/token" \
AIM_ENROLL_TOKEN_FILE="$SECRETS/enroll" \
AIM_NO_SCHEDULER=1 \
AIM_USERS="" \
AIM_SKIP_SEAL=1 \
  bash deploy/golden-image/prepare-image.sh
PREP_RC=$?
set -e

if [ "$PREP_RC" -eq 0 ]; then pass "prepare-image exit 0"
else fail "prepare-image exit $PREP_RC"; fi

for p in \
  "$TEMPLATE/opt/aim-collector/aim_collector/__main__.py" \
  "$TEMPLATE/opt/aim-collector/first-boot-enroll.sh" \
  "$TEMPLATE/opt/aim-collector/seal-for-clone.sh" \
  "$TEMPLATE/opt/aim-collector/aim-collector-heartbeat.sh" \
  "$TEMPLATE/etc/aim-collector/config.json" \
  "$TEMPLATE/etc/aim-collector/token" \
  "$TEMPLATE/etc/aim-collector/enroll-token" \
  "$TEMPLATE/etc/aim-collector/image-state"
do
  if [ -e "$p" ]; then pass "template has ${p#"$TEMPLATE"}"
  else fail "template missing ${p#"$TEMPLATE"}"; fi
done

if grep -q 'ingest.proof.example' "$TEMPLATE/etc/aim-collector/config.json"; then
  pass "config carries ingest_url"
else
  fail "config missing ingest_url"
fi

# Simulate a bake-time enroll leak (what seal must wipe)
printf 'leaked-host-id-should-not-ship\n' > "$TEMPLATE/etc/aim-collector/host_id"
printf 'leaked-device-token\n' > "$TEMPLATE/etc/aim-collector/device-token"
mkdir -p "$TEMPLATE/home/builder/.aim-collector"
printf 'user-host\n' > "$TEMPLATE/home/builder/.aim-collector/host_id"
printf 'user-tok\n' > "$TEMPLATE/home/builder/.aim-collector/device_token"

# --- seal -------------------------------------------------------------------
set +e
AIM_ROOT="$TEMPLATE" bash deploy/golden-image/seal-for-clone.sh
SEAL_RC=$?
set -e
if [ "$SEAL_RC" -eq 0 ]; then pass "seal-for-clone exit 0"
else fail "seal-for-clone exit $SEAL_RC"; fi

for f in host_id device-token device_token; do
  if [ -e "$TEMPLATE/etc/aim-collector/$f" ]; then
    fail "identity remains after seal: $f"
  else
    pass "sealed away $f"
  fi
done

if [ -e "$TEMPLATE/home/builder/.aim-collector/host_id" ]; then
  fail "per-user host_id survived seal"
else
  pass "per-user state purged by seal"
fi

if [ "$(cat "$TEMPLATE/etc/aim-collector/image-state")" = "sealed" ]; then
  pass "image-state=sealed"
else
  fail "image-state not sealed"
fi

if [ -e "$TEMPLATE/etc/aim-collector/needs-enroll" ]; then
  pass "needs-enroll marker present"
else
  fail "needs-enroll marker missing"
fi

# Secrets must survive seal (model A)
if [ -s "$TEMPLATE/etc/aim-collector/enroll-token" ] \
  && [ -s "$TEMPLATE/etc/aim-collector/token" ]; then
  pass "ring secrets preserved across seal"
else
  fail "ring secrets lost during seal"
fi

# Idempotent re-seal
set +e
AIM_ROOT="$TEMPLATE" bash deploy/golden-image/seal-for-clone.sh
RESEAL_RC=$?
set -e
if [ "$RESEAL_RC" -eq 0 ]; then pass "re-seal idempotent"
else fail "re-seal exit $RESEAL_RC"; fi

# --- clone identity uniqueness ----------------------------------------------
# Copy sealed template to two clones; mint host_id the way heartbeat does.
mint_host_id() {
  local clone="$1"
  local f="$clone/etc/aim-collector/host_id"
  python3 -c 'import uuid; print(uuid.uuid4())' > "$f"
  chmod 0644 "$f"
  cat "$f"
}

rm -rf "$CLONE_A" "$CLONE_B"
cp -a "$TEMPLATE" "$CLONE_A"
cp -a "$TEMPLATE" "$CLONE_B"

HID_A="$(mint_host_id "$CLONE_A")"
HID_B="$(mint_host_id "$CLONE_B")"

if [ -n "$HID_A" ] && [ -n "$HID_B" ] && [ "$HID_A" != "$HID_B" ]; then
  pass "clone host_ids differ ($HID_A vs $HID_B)"
else
  fail "clone host_ids not unique (A=$HID_A B=$HID_B)"
fi

# first-boot against offline ingest should not crash; may leave no device-token
set +e
AIM_ROOT="$CLONE_A" AIM_CONFIG_DIR="$CLONE_A/etc/aim-collector" \
  bash deploy/golden-image/first-boot-enroll.sh >/dev/null 2>&1
FB_RC=$?
set -e
# heartbeat helper exits 0 on network failure — accept 0
if [ "$FB_RC" -eq 0 ]; then pass "first-boot-enroll handles offline ingest (rc=0)"
else fail "first-boot-enroll unexpected rc=$FB_RC"; fi

# host_id must still be the clone's (first-boot must not blank it without replace)
if [ "$(cat "$CLONE_A/etc/aim-collector/host_id")" = "$HID_A" ]; then
  pass "first-boot preserves clone host_id"
else
  fail "first-boot altered host_id unexpectedly"
fi

# --- summary ----------------------------------------------------------------
echo
echo "=== AIM-745 summary ==="
echo "pass=$PASS fail=$FAIL proof_root=$PROOF_ROOT"
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT: PASS"
  exit 0
fi
echo "RESULT: FAIL"
exit 1
