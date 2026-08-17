#!/usr/bin/env python3
"""Sync the canonical fleet enroll/heartbeat client into each collector.

The endpoint collectors ship as standalone packages, so each carries a
verbatim vendored copy of the shared enroll/heartbeat client. The single
source of truth is `collectors/enroll-client/enroll.py`; this script copies
it into:

    collectors/claude-code/aim_collector/enroll.py
    collectors/cursor/cursor_collector/enroll.py
    collectors/kilo-code/kilo_collector/enroll.py
    collectors/kimi-code/kimi_collector/enroll.py
    collectors/github-copilot/copilot_collector/enroll.py

The client depends only on each package's `__version__`, `config`, and
`state` modules (identical interfaces across the four collectors), so the
copy is byte-for-byte identical — no per-collector edits.

Usage:
    python3 scripts/sync_enroll_client.py          # write the copies
    python3 scripts/sync_enroll_client.py --check  # verify only (CI)
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "collectors" / "enroll-client" / "enroll.py"
TARGETS = [
    ROOT / "collectors" / "claude-code" / "aim_collector" / "enroll.py",
    ROOT / "collectors" / "cursor" / "cursor_collector" / "enroll.py",
    ROOT / "collectors" / "kilo-code" / "kilo_collector" / "enroll.py",
    ROOT / "collectors" / "kimi-code" / "kimi_collector" / "enroll.py",
    ROOT / "collectors" / "github-copilot" / "copilot_collector" / "enroll.py",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify copies are in sync, do not write")
    args = ap.parse_args()

    canonical = CANONICAL.read_bytes()
    stale = [t for t in TARGETS if not t.exists() or t.read_bytes() != canonical]

    if args.check:
        if stale:
            print("OUT OF SYNC (run scripts/sync_enroll_client.py):")
            for t in stale:
                print(f"  {t.relative_to(ROOT)}")
            return 1
        print(f"all {len(TARGETS)} collector enroll-client copies are in sync")
        return 0

    for t in stale:
        t.write_bytes(canonical)
        print(f"synced {t.relative_to(ROOT)}")
    if not stale:
        print("already in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main())
