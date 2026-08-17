#!/usr/bin/env python3
"""Sync the canonical spool/flush client into each collector (AIM-200).

The endpoint collectors ship as standalone packages, so each carries a
verbatim vendored copy of the shared spool client. The single source of
truth is `collectors/spool-client/spool.py`; this script copies it into:

    collectors/claude-code/aim_collector/spool.py
    collectors/cursor/cursor_collector/spool.py
    collectors/kilo-code/kilo_collector/spool.py
    collectors/kimi-code/kimi_collector/spool.py
    collectors/github-copilot/copilot_collector/spool.py

Why this exists: the four copies had already drifted. AIM-127 added ingest
backpressure handling to the claude-code copy only, so the other three kept
hammering an overloaded ingest; and AIM-200's silent-drop bug (HTTP 200 read
as full acceptance) was present in all four but only reported against one.
The client depends only on each package's `config`, `identity` and `state`
modules — identical interfaces across the four collectors — so the copy is
byte-for-byte identical, and CI fails if any copy drifts.

Usage:
    python3 scripts/sync_spool_client.py          # write the copies
    python3 scripts/sync_spool_client.py --check  # verify only (CI)
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "collectors" / "spool-client" / "spool.py"
TARGETS = [
    ROOT / "collectors" / "claude-code" / "aim_collector" / "spool.py",
    ROOT / "collectors" / "cursor" / "cursor_collector" / "spool.py",
    ROOT / "collectors" / "kilo-code" / "kilo_collector" / "spool.py",
    ROOT / "collectors" / "kimi-code" / "kimi_collector" / "spool.py",
    ROOT / "collectors" / "github-copilot" / "copilot_collector" / "spool.py",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify copies are in sync, do not write")
    args = ap.parse_args()

    canonical = CANONICAL.read_bytes()
    stale = [t for t in TARGETS if not t.exists() or t.read_bytes() != canonical]

    if args.check:
        if stale:
            print("OUT OF SYNC (run scripts/sync_spool_client.py):")
            for t in stale:
                print(f"  {t.relative_to(ROOT)}")
            return 1
        print(f"all {len(TARGETS)} collector spool-client copies are in sync")
        return 0

    for t in stale:
        t.write_bytes(canonical)
        print(f"synced {t.relative_to(ROOT)}")
    if not stale:
        print("already in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main())
