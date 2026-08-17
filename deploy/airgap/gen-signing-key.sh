#!/usr/bin/env bash
# Generate an Ed25519 keypair for AIM air-gap bundle signing.
#
# Usage:
#   deploy/airgap/gen-signing-key.sh [output-dir]
#
# Writes:
#   <dir>/aim-airgap-ed25519.pem      private key (PEM) — CI / release only
#   <dir>/aim-airgap-ed25519.pub.pem  public key (PEM)  — ship with targets
#   <dir>/aim-airgap-ed25519.pub.b64  raw 32-byte public key, base64 (optional pin)
#
# Private key never goes in the transfer medium. Distribute the public key via
# a separate trust path (image, MDM, HSM export, signed config).
set -euo pipefail

OUT_DIR="${1:-deploy/airgap/keys}"
mkdir -p "$OUT_DIR"

PRIV="$OUT_DIR/aim-airgap-ed25519.pem"
PUB="$OUT_DIR/aim-airgap-ed25519.pub.pem"
PUB_B64="$OUT_DIR/aim-airgap-ed25519.pub.b64"

if [[ -e "$PRIV" || -e "$PUB" ]]; then
  echo "error: key material already exists in ${OUT_DIR}; refusing to overwrite." >&2
  echo "       Move/rotate keys deliberately, then re-run." >&2
  exit 1
fi

openssl genpkey -algorithm ED25519 -out "$PRIV"
chmod 600 "$PRIV"
openssl pkey -in "$PRIV" -pubout -out "$PUB"
chmod 644 "$PUB"

# Raw SPKI public key bytes → last 32 bytes are the Ed25519 public key.
# openssl asn1parse is fragile across versions; use pkey -pubout -outform DER
# and take the final 32 bytes (Ed25519 SPKI is fixed-length).
python3 - "$PUB" "$PUB_B64" <<'PY'
import base64, sys
from pathlib import Path
pub_pem = Path(sys.argv[1]).read_bytes()
# Strip PEM armor
body = b"".join(
    line for line in pub_pem.splitlines()
    if not line.startswith(b"-----")
)
der = base64.b64decode(body)
if len(der) < 32:
    raise SystemExit(f"unexpected SPKI length {len(der)}")
raw = der[-32:]
Path(sys.argv[2]).write_text(base64.b64encode(raw).decode("ascii") + "\n", encoding="utf-8")
print(f"raw_pub_b64={base64.b64encode(raw).decode('ascii')}")
PY

echo
echo "Wrote:"
echo "  private: $PRIV  (keep offline / in CI secrets; never in the air-gap USB)"
echo "  public:  $PUB"
echo "  raw b64: $PUB_B64"
echo
echo "Sign a bundle:"
echo "  AIM_AIRGAP_SIGNING_KEY=$PRIV deploy/airgap/sign-bundle.sh deploy/airgap/out/aim-airgap-VERSION.tar.gz"
echo "Verify on target:"
echo "  AIM_AIRGAP_PUBKEY=$PUB deploy/airgap/verify-bundle.sh aim-airgap-VERSION.tar.gz"
