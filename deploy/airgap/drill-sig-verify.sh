#!/usr/bin/env bash
# — offline air-gap signature verification drill.
#
# Builds a synthetic mini-bundle (no docker / no full image build), signs it,
# verifies (positive path), tampers and confirms reject (negative path), and
# writes evidence under docs/deployment/drills/.
#
# Usage (from repo root):
#   deploy/airgap/drill-sig-verify.sh
#   OUT_DIR=/tmp/aim747-drill deploy/airgap/drill-sig-verify.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DRILL_ID="aim747-${STAMP}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/deploy/airgap/out/drill-${DRILL_ID}}"
EVIDENCE_MD="${EVIDENCE_MD:-${REPO_ROOT}/docs/deployment/drills/drill-${DRILL_ID}.md}"
EVIDENCE_JSON="${EVIDENCE_JSON:-${REPO_ROOT}/docs/deployment/drills/drill-${DRILL_ID}.json}"

mkdir -p "$OUT_DIR" "$(dirname "$EVIDENCE_MD")"
KEY_DIR="$OUT_DIR/keys"
STAGE="$OUT_DIR/stage/aim-airgap-drill"
mkdir -p "$STAGE" "$KEY_DIR"

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RESULTS=()
record() {
  # record <id> <PASS|FAIL> <detail>
  RESULTS+=("$1|$2|$3")
  printf '  [%s] %s — %s\n' "$2" "$1" "$3"
}

echo "==> signature verification drill (${DRILL_ID})"
echo "    work dir: $OUT_DIR"

# --- 1. Generate ephemeral drill keys (never production) ---
rm -f "$KEY_DIR"/* 2>/dev/null || true
# gen-signing-key refuses overwrite; empty dir is fine
deploy/airgap/gen-signing-key.sh "$KEY_DIR"
PRIV="$KEY_DIR/aim-airgap-ed25519.pem"
PUB="$KEY_DIR/aim-airgap-ed25519.pub.pem"
FP="$(openssl pkey -pubin -in "$PUB" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
record "gen_keypair" "PASS" "fp=${FP}"

# --- 2. Synthetic mini-bundle (represents real tarball shape) ---
echo "offline core install kit signature drill" > "$STAGE/README-airgap.md"
printf '%s\n' '#!/bin/sh' 'echo drill-install-noop' > "$STAGE/install-offline.sh"
chmod +x "$STAGE/install-offline.sh"
# MANIFEST file hashes match build-bundle.sh layout
{
  cat <<HDR
AIM air-gapped bundle
Version: drill
Built:   ${STARTED_AT}
Helm chart: drill synthetic (no images)

Images (uncompressed size as reported by docker):
  (none — signature drill only)

Files (sha256):
HDR
  (cd "$STAGE" && find . -type f ! -name MANIFEST.txt -print0 | sort -z | xargs -0 sha256sum | sed 's|  \./|  |')
} > "$STAGE/MANIFEST.txt"

BUNDLE="$OUT_DIR/aim-airgap-drill.tar.gz"
tar -czf "$BUNDLE" -C "$(dirname "$STAGE")" "$(basename "$STAGE")"
record "build_synthetic_bundle" "PASS" "bytes=$(wc -c < "$BUNDLE")"

# --- 3. Sign ---
AIM_AIRGAP_SIGNING_KEY="$PRIV" deploy/airgap/sign-bundle.sh "$BUNDLE"
for f in "${BUNDLE}.sha256" "${BUNDLE}.sig" "${BUNDLE}.sha256.sig" "${BUNDLE}.sigmeta.json"; do
  [[ -f "$f" ]] || { record "sign_artifacts" "FAIL" "missing $f"; break; }
done
if [[ -f "${BUNDLE}.sig" ]]; then
  record "sign_artifacts" "PASS" "sha256+sig+sha256.sig+sigmeta"
fi

# --- 4. Positive verify (pre-unpack) ---
if AIM_AIRGAP_PUBKEY="$PUB" AIM_AIRGAP_KEY_FINGERPRINT="$FP" \
    deploy/airgap/verify-bundle.sh "$BUNDLE"; then
  record "verify_positive" "PASS" "pre-unpack signature + digest"
else
  record "verify_positive" "FAIL" "expected success"
fi

# --- 5. Positive verify with inner MANIFEST ---
UNPACK="$OUT_DIR/unpacked"
rm -rf "$UNPACK"
mkdir -p "$UNPACK"
tar -xzf "$BUNDLE" -C "$UNPACK"
INNER="$(find "$UNPACK" -mindepth 1 -maxdepth 1 -type d | head -1)"
if AIM_AIRGAP_PUBKEY="$PUB" \
    deploy/airgap/verify-bundle.sh "$BUNDLE" --check-manifest "$INNER"; then
  record "verify_manifest" "PASS" "inner MANIFEST.txt hashes"
else
  record "verify_manifest" "FAIL" "manifest check"
fi

# --- 6. Negative: tampered tarball must fail ---
TAMPER="$OUT_DIR/aim-airgap-drill-tampered.tar.gz"
cp "$BUNDLE" "$TAMPER"
cp "${BUNDLE}.sha256" "${TAMPER}.sha256"
cp "${BUNDLE}.sig" "${TAMPER}.sig"
cp "${BUNDLE}.sha256.sig" "${TAMPER}.sha256.sig"
# Flip one byte in the tarball
python3 - "$TAMPER" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
data[-1] = (data[-1] + 1) % 256
p.write_bytes(data)
PY
if AIM_AIRGAP_PUBKEY="$PUB" deploy/airgap/verify-bundle.sh "$TAMPER" >/dev/null 2>&1; then
  record "verify_tamper_reject" "FAIL" "tampered tarball was accepted"
else
  record "verify_tamper_reject" "PASS" "tampered tarball rejected"
fi

# --- 7. Negative: wrong key must fail ---
WRONG_DIR="$OUT_DIR/wrong-keys"
rm -rf "$WRONG_DIR"
deploy/airgap/gen-signing-key.sh "$WRONG_DIR" >/dev/null
if AIM_AIRGAP_PUBKEY="$WRONG_DIR/aim-airgap-ed25519.pub.pem" \
    deploy/airgap/verify-bundle.sh "$BUNDLE" >/dev/null 2>&1; then
  record "verify_wrong_key_reject" "FAIL" "wrong pubkey accepted"
else
  record "verify_wrong_key_reject" "PASS" "wrong pubkey rejected"
fi

# --- 8. Negative: missing .sig must fail ---
MISSING="$OUT_DIR/aim-airgap-drill-nosig.tar.gz"
cp "$BUNDLE" "$MISSING"
cp "${BUNDLE}.sha256" "${MISSING}.sha256"
# deliberately omit .sig
if AIM_AIRGAP_PUBKEY="$PUB" deploy/airgap/verify-bundle.sh "$MISSING" >/dev/null 2>&1; then
  record "verify_missing_sig_reject" "FAIL" "unsigned bundle accepted"
else
  record "verify_missing_sig_reject" "PASS" "missing .sig rejected"
fi

ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
FAILS=0
for row in "${RESULTS[@]}"; do
  IFS='|' read -r _id status _detail <<<"$row"
  if [[ "$status" != "PASS" ]]; then
    FAILS=$((FAILS + 1))
  fi
done
if [[ "$FAILS" -eq 0 ]]; then
  OVERALL="PASS"
else
  OVERALL="FAIL"
fi

# --- Evidence files ---
{
  echo "# — Air-gap signature verification drill"
  echo
  echo "| Field | Value |"
  echo "| --- | --- |"
  echo "| **drill_id** | \`${DRILL_ID}\` |"
  echo "| **result** | **${OVERALL}** |"
  echo "| **started_utc** | ${STARTED_AT} |"
  echo "| **ended_utc** | ${ENDED_AT} |"
  echo "| **alg** | Ed25519 (OpenSSL pkeyutl -rawin) |"
  echo "| **key_fingerprint_sha256** | \`${FP}\` |"
  echo "| **bundle** | \`$(basename "$BUNDLE")\` ($(wc -c < "$BUNDLE") bytes) |"
  echo
  echo "## Checks"
  echo
  echo "| Check | Result | Detail |"
  echo "| --- | --- | --- |"
  for row in "${RESULTS[@]}"; do
    IFS='|' read -r id status detail <<<"$row"
    echo "| \`${id}\` | **${status}** | ${detail} |"
  done
  echo
  echo "## Procedure exercised"
  echo
  echo "1. \`deploy/airgap/gen-signing-key.sh\` — ephemeral drill keypair"
  echo "2. Synthetic mini-bundle with MANIFEST.txt (no docker images)"
  echo "3. \`deploy/airgap/sign-bundle.sh\` — \`.sha256\` + \`.sig\` + \`.sha256.sig\` + \`.sigmeta.json\`"
  echo "4. \`deploy/airgap/verify-bundle.sh\` positive path + \`--check-manifest\`"
  echo "5. Negative: tampered tarball, wrong pubkey, missing \`.sig\`"
  echo
  echo "## Operator takeaway"
  echo
  echo "- Verify **before** \`tar -xzf\` / \`install-offline.sh\`."
  echo "- Public key is pre-pinned on the target (fingerprint in change ticket)."
  echo "- Private key stays on the connected build host / CI secret store."
  echo "- Full product flow: \`build-bundle.sh\` then \`sign-bundle.sh\` (or"
  echo "  \`AIM_AIRGAP_SIGNING_KEY=...\` auto-sign at end of build)."
  echo
  echo "See [air-gapped-install.md](../air-gapped-install.md) § Signature verification."
} > "$EVIDENCE_MD"

python3 - "$EVIDENCE_JSON" "$DRILL_ID" "$OVERALL" "$STARTED_AT" "$ENDED_AT" "$FP" "$BUNDLE" "${RESULTS[@]}" <<'PY'
import json, sys
from pathlib import Path
out, drill_id, overall, started, ended, fp, bundle = sys.argv[1:8]
checks = []
for row in sys.argv[8:]:
    cid, status, detail = row.split("|", 2)
    checks.append({"id": cid, "result": status, "detail": detail})
Path(out).write_text(
    json.dumps(
        {
            "schema": "aim.airgap-sig-drill/v1",
            "drill_id": drill_id,
            "result": overall,
            "started_utc": started,
            "ended_utc": ended,
            "alg": "Ed25519",
            "key_fingerprint_sha256": fp,
            "bundle": Path(bundle).name,
            "bundle_bytes": Path(bundle).stat().st_size,
            "checks": checks,
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY

echo
echo "Drill ${OVERALL}: ${DRILL_ID}"
echo "  evidence: $EVIDENCE_MD"
echo "  json:     $EVIDENCE_JSON"
echo "  artifacts:$OUT_DIR"
[[ "$OVERALL" == "PASS" ]]
