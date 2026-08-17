#!/usr/bin/env bash
# Sign an AIM air-gap tarball with Ed25519 (OpenSSL).
#
# Usage:
#   AIM_AIRGAP_SIGNING_KEY=/path/to/priv.pem \
#     deploy/airgap/sign-bundle.sh deploy/airgap/out/aim-airgap-1.4.0.tar.gz
#
# Also accepts:
#   deploy/airgap/sign-bundle.sh <bundle.tar.gz> <priv.pem>
#
# Produces next to the tarball:
#   <bundle>.sha256          single-line sha256sum of the tarball
#   <bundle>.sig             raw Ed25519 signature over the tarball bytes
#   <bundle>.sha256.sig      signature over the .sha256 file (human-readable path)
#   <bundle>.sigmeta.json    metadata (alg, key fingerprint, signed_at, digests)
#
# Cosign is intentionally not required: air-gapped targets often lack network
# for Rekor, and cosign may not be installed. OpenSSL Ed25519 verifies offline
# with only the public PEM that Security already pinned.
set -euo pipefail

BUNDLE="${1:-}"
KEY="${2:-${AIM_AIRGAP_SIGNING_KEY:-}}"

if [[ -z "$BUNDLE" || -z "$KEY" ]]; then
  echo "usage: AIM_AIRGAP_SIGNING_KEY=priv.pem $0 <aim-airgap-VERSION.tar.gz> [priv.pem]" >&2
  exit 2
fi
if [[ ! -f "$BUNDLE" ]]; then
  echo "error: bundle not found: $BUNDLE" >&2
  exit 1
fi
if [[ ! -f "$KEY" ]]; then
  echo "error: signing key not found: $KEY" >&2
  exit 1
fi

# Refuse non-Ed25519 keys so verify-bundle and docs stay one algorithm.
ALG="$(openssl pkey -in "$KEY" -text -noout 2>/dev/null | awk '/ED25519|Ed25519/{print; exit}')"
if [[ -z "$ALG" ]]; then
  echo "error: signing key must be Ed25519 PEM (generate with deploy/airgap/gen-signing-key.sh)" >&2
  exit 1
fi

SHA_FILE="${BUNDLE}.sha256"
SIG_FILE="${BUNDLE}.sig"
SHA_SIG_FILE="${BUNDLE}.sha256.sig"
META_FILE="${BUNDLE}.sigmeta.json"

echo "==> Digest ${BUNDLE}"
# Portable single-file sha256sum line (GNU format: "<hex>  <basename>")
(
  cd "$(dirname "$BUNDLE")"
  sha256sum "$(basename "$BUNDLE")"
) > "$SHA_FILE"

echo "==> Sign tarball -> ${SIG_FILE}"
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$BUNDLE" -out "$SIG_FILE"

echo "==> Sign digest file -> ${SHA_SIG_FILE}"
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$SHA_FILE" -out "$SHA_SIG_FILE"

DIGEST="$(awk '{print $1}' "$SHA_FILE")"
# Fingerprint = sha256 of DER public key (stable id operators can pin).
PUB_TMP="$(mktemp)"
trap 'rm -f "$PUB_TMP"' EXIT
openssl pkey -in "$KEY" -pubout -outform DER -out "$PUB_TMP"
FP="$(sha256sum "$PUB_TMP" | awk '{print $1}')"
SIGNED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUNDLE_BASE="$(basename "$BUNDLE")"

python3 - "$META_FILE" "$BUNDLE_BASE" "$DIGEST" "$FP" "$SIGNED_AT" <<'PY'
import json, sys
from pathlib import Path
out, bundle, digest, fp, signed_at = sys.argv[1:6]
meta = {
    "schema": "aim.airgap-sigmeta/v1",
    "alg": "Ed25519",
    "bundle": bundle,
    "sha256": digest,
    "key_fingerprint_sha256": fp,
    "signed_at": signed_at,
    "covers": [
        "detached signature over full tarball bytes (.sig)",
        "detached signature over .sha256 digest file (.sha256.sig)",
    ],
    "verify": "AIM_AIRGAP_PUBKEY=pub.pem deploy/airgap/verify-bundle.sh " + bundle,
}
Path(out).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
PY

echo
echo "Signed:"
echo "  bundle:  $BUNDLE"
echo "  sha256:  $DIGEST"
echo "  key fp:  $FP"
echo "  meta:    $META_FILE"
echo
echo "Transfer as a set (do NOT put the private key on the medium):"
echo "  ${BUNDLE_BASE}"
echo "  ${BUNDLE_BASE}.sha256"
echo "  ${BUNDLE_BASE}.sig"
echo "  ${BUNDLE_BASE}.sha256.sig"
echo "  ${BUNDLE_BASE}.sigmeta.json"
echo "Public key travels on a separate trust path (or is pre-pinned on the target)."
