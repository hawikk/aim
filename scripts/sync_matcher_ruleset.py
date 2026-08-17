#!/usr/bin/env python3
"""Sync the canonical matcher ruleset into each collector package.

The endpoint collectors ship as standalone packages (Intune etc.), so each
carries a verbatim vendored copy of the shared ruleset. The single source of
truth is `collectors/matcher-ruleset/matchers.py`; this script copies it into:

    collectors/claude-code/aim_collector/matchers.py
    collectors/cursor/cursor_collector/matchers.py
    collectors/kilo-code/kilo_collector/matchers.py
    collectors/kimi-code/kimi_collector/matchers.py

Usage:
    python3 scripts/sync_matcher_ruleset.py          # write the copies
    python3 scripts/sync_matcher_ruleset.py --check  # verify only (CI)

After changing the ruleset, also review `collectors/matcher-fixtures/evasion.json`
and regenerate `docs/security/detector-evasion-capability.md` with
`scripts/matcher_evasion_report.py`.
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "collectors" / "matcher-ruleset" / "matchers.py"
TARGETS = [
    ROOT / "collectors" / "claude-code" / "aim_collector" / "matchers.py",
    ROOT / "collectors" / "cursor" / "cursor_collector" / "matchers.py",
    ROOT / "collectors" / "kilo-code" / "kilo_collector" / "matchers.py",
    ROOT / "collectors" / "kimi-code" / "kimi_collector" / "matchers.py",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify copies are in sync, do not write")
    args = ap.parse_args()

    canonical = CANONICAL.read_bytes()
    stale = [t for t in TARGETS if not t.exists() or t.read_bytes() != canonical]

    if args.check:
        if stale:
            print("OUT OF SYNC (run scripts/sync_matcher_ruleset.py):")
            for t in stale:
                print(f"  {t.relative_to(ROOT)}")
            return 1
        print(f"all {len(TARGETS)} collector matcher copies are in sync")
        return 0

    for t in stale:
        t.write_bytes(canonical)
        print(f"synced {t.relative_to(ROOT)}")
    if not stale:
        print("already in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main())
