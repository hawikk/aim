#!/usr/bin/env bash
# Verify an AIM air-gap tarball signature offline (AIM-747).
#
# Usage:
#   AIM_AIRGAP_PUBKEY=/path/to/pub.pem \
#     deploy/airgap/verify-bundle.sh aim-airgap-1.4.0.tar.gz
#
#   deploy/airgap/verify-bundle.sh aim-airgap-1.4.0.tar.gz /path/to/pub.pem
#
#   deploy/airgap/verify-bundle.sh bundle.tar.gz pub.pem --check-manifest ./aim-airgap-1.4.0
#
# Checks (fail-closed; any failure exits non-zero):
#   1. .sha256 matches the tarball bytes (integrity)
#   2. .sig is a valid Ed25519 signature over the tarball (authenticity)
#   3. .sha256.sig is a valid Ed25519 signature over the digest file
#   4. Optional: after unpack, MANIFEST.txt inner file hashes (--check-manifest DIR)
#
# Never loads images or runs install until this returns 0.
set -euo pipefail

BUNDLE=""
PUBKEY="${AIM_AIRGAP_PUBKEY:-}"
MANIFEST_DIR=""
EXPECT_FP="${AIM_AIRGAP_KEY_FINGERPRINT:-}"
POSITIONAL=()

usage() {
  cat <<'EOF' >&2
usage: AIM_AIRGAP_PUBKEY=pub.pem verify-bundle.sh <bundle.tar.gz>
       verify-bundle.sh <bundle.tar.gz> <pub.pem>
       verify-bundle.sh <bundle.tar.gz> [pub.pem] --check-manifest <untarred-dir>

Env:
  AIM_AIRGAP_PUBKEY            path to Ed25519 public PEM
  AIM_AIRGAP_KEY_FINGERPRINT   optional sha256 of DER public key (pin)
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-manifest)
      [[ $# -ge 2 ]] || usage
      MANIFEST_DIR="$2"
      shift 2
      ;;
    -h|--help) usage ;;
    --) shift; POSITIONAL+=("$@"); break ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL[@]} -lt 1 ]]; then
  usage
fi
BUNDLE="${POSITIONAL[0]}"
if [[ ${#POSITIONAL[@]} -ge 2 ]]; then
  PUBKEY="${POSITIONAL[1]}"
fi

if [[ -z "$BUNDLE" || -z "$PUBKEY" ]]; then
  usage
fi
if [[ ! -f "$BUNDLE" ]]; then
  echo "error: bundle not found: $BUNDLE" >&2
  exit 1
fi
if [[ ! -f "$PUBKEY" ]]; then
  echo "error: public key not found: $PUBKEY" >&2
  exit 1
fi

SHA_FILE="${BUNDLE}.sha256"
SIG_FILE="${BUNDLE}.sig"
SHA_SIG_FILE="${BUNDLE}.sha256.sig"
META_FILE="${BUNDLE}.sigmeta.json"

for f in "$SHA_FILE" "$SIG_FILE" "$SHA_SIG_FILE"; do
  if [[ ! -f "$f" ]]; then
    echo "error: missing companion file: $f" >&2
    echo "       Air-gap install kit requires tarball + .sha256 + .sig + .sha256.sig" >&2
    exit 1
  fi
done

fail() {
  echo "VERIFY_FAIL: $*" >&2
  exit 1
}

pass() {
  echo "OK  $*"
}

echo "==> Verifying ${BUNDLE}"

PUB_DER="$(mktemp)"
trap 'rm -f "$PUB_DER"' EXIT
openssl pkey -pubin -in "$PUBKEY" -outform DER -out "$PUB_DER" 2>/dev/null \
  || fail "public key is not a readable PEM public key"
FP="$(sha256sum "$PUB_DER" | awk '{print $1}')"
pass "public key fingerprint sha256=${FP}"

if [[ -n "$EXPECT_FP" ]]; then
  want="${EXPECT_FP#sha256:}"
  if [[ "$want" != "$FP" ]]; then
    fail "key fingerprint mismatch (expected ${want}, got ${FP})"
  fi
  pass "key fingerprint matches AIM_AIRGAP_KEY_FINGERPRINT"
fi

if [[ -f "$META_FILE" ]]; then
  meta_fp="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("key_fingerprint_sha256",""))' "$META_FILE")"
  if [[ -n "$meta_fp" && "$meta_fp" != "$FP" ]]; then
    fail "sigmeta.json key fingerprint ${meta_fp} != pubkey ${FP}"
  fi
  if [[ -n "$meta_fp" ]]; then
    pass "sigmeta.json key fingerprint matches pubkey"
  fi
fi

echo "==> Check tarball sha256"
(
  cd "$(dirname "$BUNDLE")"
  sha256sum -c "$(basename "$SHA_FILE")"
) || fail "tarball digest mismatch (corruption or swap)"
pass "tarball matches ${SHA_FILE}"

echo "==> Check Ed25519 signature over tarball"
openssl pkeyutl -verify -pubin -inkey "$PUBKEY" -rawin -in "$BUNDLE" -sigfile "$SIG_FILE" \
  || fail "tarball signature invalid"
pass "tarball signature valid (${SIG_FILE})"

echo "==> Check Ed25519 signature over digest file"
openssl pkeyutl -verify -pubin -inkey "$PUBKEY" -rawin -in "$SHA_FILE" -sigfile "$SHA_SIG_FILE" \
  || fail "digest-file signature invalid"
pass "digest-file signature valid (${SHA_SIG_FILE})"

if [[ -n "$MANIFEST_DIR" ]]; then
  if [[ ! -d "$MANIFEST_DIR" ]]; then
    fail "--check-manifest dir not found: $MANIFEST_DIR"
  fi
  if [[ ! -f "$MANIFEST_DIR/MANIFEST.txt" ]]; then
    fail "MANIFEST.txt missing under $MANIFEST_DIR"
  fi
  echo "==> Check inner MANIFEST.txt file hashes"
  if ! grep -q 'Files (sha256)' "$MANIFEST_DIR/MANIFEST.txt"; then
    fail "MANIFEST.txt has no 'Files (sha256)' section"
  fi
  (
    cd "$MANIFEST_DIR"
    grep -A9999 'Files (sha256)' MANIFEST.txt | tail -n +2 | awk 'NF{print}' | sha256sum -c -
  ) || fail "inner MANIFEST.txt hash check failed"
  pass "inner MANIFEST.txt hashes OK"
fi

echo
echo "VERIFY_OK  ${BUNDLE}"
echo "Safe to unpack and run ./install-offline.sh (after site change control)."
