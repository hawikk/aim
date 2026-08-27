#!/usr/bin/env python3
"""Fail on broken *relative* markdown links under docs/ (AIM-1212).

Public snapshot CI should run this so unpublished ADR targets cannot
reappear. Skip targets that are deliberately outside this tree by using
plain text instead of a markdown link.

Usage:
    python3 scripts/check_docs_links.py
    python3 scripts/check_docs_links.py --root docs
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def iter_links(root: Path) -> list[tuple[Path, str]]:
    found: list[tuple[Path, str]] = []
    for path in root.rglob("*.md"):
        text = path.read_text(errors="replace")
        for m in LINK_RE.finditer(text):
            url = m.group(1).strip()
            if url.startswith(("http://", "https://", "mailto:", "#")):
                continue
            found.append((path, url.split("#", 1)[0].split("?", 1)[0]))
    return found


def missing(root: Path) -> list[str]:
    failures: list[str] = []
    root = root.resolve()
    for path, target in iter_links(root):
        if not target:
            continue
        dest = (path.parent / target).resolve()
        try:
            dest.relative_to(root)
        except ValueError:
            # ../CHANGELOG.md is allowed if it exists in the repo.
            if dest.exists():
                continue
            failures.append(f"{path}: {target} (outside docs/ and missing)")
            continue
        if not dest.exists():
            failures.append(f"{path}: {target} (missing)")
    return failures


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=REPO_ROOT / "docs")
    args = p.parse_args(argv)
    if not args.root.exists():
        print(f"missing {args.root}", file=sys.stderr)
        return 1
    fails = missing(args.root)
    if fails:
        print(f"{len(fails)} broken relative link(s):", file=sys.stderr)
        for f in fails:
            print(f, file=sys.stderr)
        return 1
    print(f"OK relative links under {args.root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
