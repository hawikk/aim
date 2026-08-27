#!/usr/bin/env python3
"""Cut CHANGELOG.md [Unreleased] into a dated version section.

Run this on the private working repo **before** tagging ``vX.Y.Z``.
``release-cli.yml`` then fail-closes if the tag version is missing.

Usage:
    python3 scripts/cut_changelog.py 0.1.5
    python3 scripts/cut_changelog.py 0.1.5 --date 2026-08-27 --allow-empty
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

UNRELEASED_RE = re.compile(
    r"^## \[Unreleased\]\n(?P<body>.*?)(?=^## \[)",
    re.M | re.S,
)
FOOTER_UNRELEASED_RE = re.compile(
    r"^\[Unreleased\]:\s+\S+\s*$",
    re.M,
)


def cut(text: str, version: str, date: str, allow_empty: bool) -> str:
    if re.search(rf"^## \[{re.escape(version)}\]", text, re.M):
        raise SystemExit(f"CHANGELOG.md already has ## [{version}]")
    m = UNRELEASED_RE.search(text)
    if not m:
        raise SystemExit("CHANGELOG.md is missing ## [Unreleased] before the next section")
    body = m.group("body")
    if not body.strip() and not allow_empty:
        raise SystemExit(
            "Unreleased is empty — add notes, or pass --allow-empty if the "
            "tag truly has nothing to list"
        )
    replacement = f"## [Unreleased]\n\n## [{version}] - {date}\n{body}"
    text = UNRELEASED_RE.sub(replacement, text, count=1)
    new_unreleased = f"[Unreleased]: https://github.com/hawikk/aim/compare/v{version}...HEAD"
    if FOOTER_UNRELEASED_RE.search(text):
        text = FOOTER_UNRELEASED_RE.sub(new_unreleased, text, count=1)
    else:
        text = text.rstrip() + "\n\n" + new_unreleased + "\n"
    return text


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("version", help="X.Y.Z without a leading v")
    p.add_argument("--date", default=dt.date.today().isoformat())
    p.add_argument("--allow-empty", action="store_true")
    p.add_argument("--file", type=Path, default=CHANGELOG)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        print("version must be X.Y.Z", file=sys.stderr)
        return 2
    text = args.file.read_text()
    out = cut(text, args.version, args.date, args.allow_empty)
    if args.dry_run:
        sys.stdout.write(out)
        return 0
    args.file.write_text(out)
    print(f"cut [{args.version}] - {args.date} in {args.file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
