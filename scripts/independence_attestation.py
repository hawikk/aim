#!/usr/bin/env python3
"""Continuous independence attestation for Dimension 16 (AIM-639 / AIM-751).

Exit 0 when all architectural controls for independence from the agent
execution loop are present and self-consistent; exit 1 otherwise.

Usage::

    python3 scripts/independence_attestation.py
    python3 scripts/independence_attestation.py --out independence-attestation.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.integrity.attestation import run_attestation, write_attestation  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, help="write attestation JSON here")
    ap.add_argument("--repo-root", type=Path, default=ROOT)
    args = ap.parse_args()

    att = run_attestation(args.repo_root)
    if args.out:
        write_attestation(args.out, att=att, repo_root=args.repo_root)
        print(f"wrote {args.out}")
    else:
        print(json.dumps(att.to_dict(), indent=2))

    if not att.ok:
        failed = [c for c in att.checks if not c.ok]
        print("INDEPENDENCE_ATTESTATION_FAILED:", file=sys.stderr)
        for c in failed:
            print(f"  - {c.id}: {c.detail}", file=sys.stderr)
        return 1
    print(f"INDEPENDENCE_ATTESTATION_OK passed={sum(1 for c in att.checks if c.ok)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
