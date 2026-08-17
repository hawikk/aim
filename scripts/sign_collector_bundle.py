#!/usr/bin/env python3
"""Sign a collector config or enforcement JSON as aim.signed-bundle/v1.

Ops / CI usage (private key never deployed to endpoints)::

    python3 scripts/sign_collector_bundle.py \\
      --in policies/endpoint/enforcement.json \\
      --out /tmp/enforcement.signed.json \\
      --key-file /run/secrets/aim-config-ed25519.priv.b64 \\
      --key-id aim-config-prod-2026

    python3 scripts/sign_collector_bundle.py --gen-keypair --out-dir /tmp/aim-keys

Verify::

    python3 scripts/sign_collector_bundle.py \\
      --verify /tmp/enforcement.signed.json \\
      --pubkey-file /etc/aim-collector/config-pubkey.b64
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.integrity.signing import (  # noqa: E402
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_payload,
    verify_payload,
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="infile", type=Path, help="unsigned JSON object to sign")
    ap.add_argument("--out", type=Path, help="write signed envelope here")
    ap.add_argument("--key-file", type=Path, help="base64 raw 32-byte Ed25519 private key")
    ap.add_argument("--key-id", default="aim-config", help="key id embedded in envelope")
    ap.add_argument("--verify", type=Path, help="verify a signed envelope and print payload")
    ap.add_argument("--pubkey-file", type=Path, help="base64 public key for verify")
    ap.add_argument("--gen-keypair", action="store_true", help="write test/ops keypair files")
    ap.add_argument("--out-dir", type=Path, default=Path("."), help="directory for --gen-keypair")
    args = ap.parse_args()

    if args.gen_keypair:
        priv, pub = generate_keypair()
        args.out_dir.mkdir(parents=True, exist_ok=True)
        (args.out_dir / "ed25519.priv.b64").write_text(
            base64.b64encode(priv).decode("ascii") + "\n", encoding="utf-8"
        )
        (args.out_dir / "ed25519.pub.b64").write_text(
            base64.b64encode(pub).decode("ascii") + "\n", encoding="utf-8"
        )
        print(f"wrote {args.out_dir / 'ed25519.priv.b64'} and ed25519.pub.b64")
        return 0

    if args.verify:
        env = json.loads(args.verify.read_text(encoding="utf-8"))
        pub = None
        if args.pubkey_file:
            pub = load_public_key(args.pubkey_file.read_text(encoding="utf-8"))
        ok, payload, reason = verify_payload(env, pub)
        if not ok:
            print(f"VERIFY_FAIL {reason}", file=sys.stderr)
            return 1
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if not args.infile or not args.out or not args.key_file:
        ap.error("sign mode requires --in, --out, and --key-file (or use --verify / --gen-keypair)")

    payload = json.loads(args.infile.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        print("input must be a JSON object", file=sys.stderr)
        return 2
    # If input is already an envelope, sign its payload
    if payload.get("schema") == "aim.signed-bundle/v1" and isinstance(payload.get("payload"), dict):
        payload = payload["payload"]

    priv = load_private_key(args.key_file.read_text(encoding="utf-8"))
    bundle = sign_payload(payload, priv, key_id=args.key_id)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(bundle.to_dict(), indent=2) + "\n", encoding="utf-8")
    print(f"signed {args.infile} -> {args.out} key_id={args.key_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
