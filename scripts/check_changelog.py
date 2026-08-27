#!/usr/bin/env python3
"""Fail-closed Keep-a-Changelog checks (AIM-1212).

Release CI on the private working repo calls this with ``--version`` matching
the tag so a publish cannot ship without a cut section. Public snapshot CI
calls ``--check`` so 0.1.1–0.1.4 stay documented.

Usage:
    python3 scripts/check_changelog.py --check
    python3 scripts/check_changelog.py --version 0.1.5
    python3 scripts/check_changelog.py --self-test
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
REQUIRED_RELEASES = ("0.1.1", "0.1.2", "0.1.3", "0.1.4")
HEADING_RE = re.compile(r"^## \[([^\]]+)\](?:\s*-\s*(\d{4}-\d{2}-\d{2}))?\s*$", re.M)


def headings(text: str) -> list[tuple[str, str | None]]:
    return [(m.group(1), m.group(2)) for m in HEADING_RE.finditer(text)]


def check(text: str, version: str | None = None) -> list[str]:
    failures: list[str] = []
    if "Keep a Changelog" not in text and "keepachangelog.com" not in text.lower():
        failures.append("CHANGELOG.md must declare Keep a Changelog")
    found = headings(text)
    names = [n for n, _ in found]
    if "Unreleased" not in names:
        failures.append("CHANGELOG.md is missing ## [Unreleased]")
    for rel in REQUIRED_RELEASES:
        if rel not in names:
            failures.append(f"CHANGELOG.md is missing ## [{rel}]")
    dated = [(n, d) for n, d in found if n != "Unreleased"]
    for n, d in dated:
        if d is None:
            failures.append(f"CHANGELOG.md section [{n}] is missing a date")
    if version is not None:
        if version not in names:
            failures.append(
                f"CHANGELOG.md has no ## [{version}] section — run "
                f"`python3 scripts/cut_changelog.py {version}` before tagging"
            )
        else:
            for n, d in found:
                if n == version and d is None:
                    failures.append(
                        f"CHANGELOG.md section [{version}] must be dated "
                        "(YYYY-MM-DD) before a tag"
                    )
    return failures


def self_test() -> int:
    sample = """# Changelog\nThe format is based on [Keep a Changelog](https://keepachangelog.com/).\n\n## [Unreleased]\n\n## [0.1.4] - 2026-08-18\n\n## [0.1.3] - 2026-08-17\n\n## [0.1.2] - 2026-08-17\n\n## [0.1.1] - 2026-07-31\n"""
    errs = check(sample)
    assert not errs, errs
    errs = check(sample, version="0.1.4")
    assert not errs, errs
    errs = check(sample.replace("## [0.1.2] - 2026-08-17\n\n", ""))
    assert any("0.1.2" in e for e in errs), errs
    errs = check(sample, version="0.1.5")
    assert any("0.1.5" in e for e in errs), errs
    print("self-test OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--check", action="store_true")
    p.add_argument("--version", help="require a dated section for this version")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--file", type=Path, default=CHANGELOG)
    args = p.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.file.exists():
        print(f"missing {args.file}", file=sys.stderr)
        return 1
    errs = check(args.file.read_text(), version=args.version)
    if errs:
        for e in errs:
            print(e, file=sys.stderr)
        return 1
    print(f"OK {args.file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
