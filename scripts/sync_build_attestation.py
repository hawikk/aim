#!/usr/bin/env python3
"""Sync the shared build-attestation loader into each collector.

Canonical source: ``collectors/build-identity/build_attestation.py``

Vendored into:

    collectors/claude-code/aim_collector/build_attestation.py
    collectors/cursor/cursor_collector/build_attestation.py
    collectors/kilo-code/kilo_collector/build_attestation.py
    collectors/kimi-code/kimi_collector/build_attestation.py
    collectors/grok-build/grok_collector/build_attestation.py
    collectors/github-copilot/copilot_collector/build_attestation.py

Usage:
    python3 scripts/sync_build_attestation.py          # write copies
    python3 scripts/sync_build_attestation.py --check  # CI drift check
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "collectors" / "build-identity" / "build_attestation.py"
TARGETS = [
    ROOT / "collectors" / "claude-code" / "aim_collector" / "build_attestation.py",
    ROOT / "collectors" / "cursor" / "cursor_collector" / "build_attestation.py",
    ROOT / "collectors" / "kilo-code" / "kilo_collector" / "build_attestation.py",
    ROOT / "collectors" / "kimi-code" / "kimi_collector" / "build_attestation.py",
    ROOT / "collectors" / "grok-build" / "grok_collector" / "build_attestation.py",
    ROOT / "collectors" / "github-copilot" / "copilot_collector" / "build_attestation.py",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify copies are in sync")
    args = ap.parse_args()

    canonical = CANONICAL.read_bytes()
    stale = [t for t in TARGETS if not t.exists() or t.read_bytes() != canonical]

    if args.check:
        if stale:
            print("OUT OF SYNC (run scripts/sync_build_attestation.py):")
            for t in stale:
                print(f"  {t.relative_to(ROOT)}")
            return 1
        print(f"all {len(TARGETS)} collector build_attestation copies are in sync")
        return 0

    for t in stale:
        t.parent.mkdir(parents=True, exist_ok=True)
        t.write_bytes(canonical)
        print(f"synced {t.relative_to(ROOT)}")
    if not stale:
        print("already in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main())
