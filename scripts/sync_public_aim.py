#!/usr/bin/env python3
"""Copy the public-funnel overlay onto a hawikk/aim checkout (AIM-1212).

This is **not** a full private→public export. The Community snapshot is a
curated tree; blindly rsyncing the working repo would publish fleet
evidence. This script only overlays the funnel files (changelog, docs
site, issue templates, changelog helpers) and then scans the destination
for denylisted paths.

Usage:
    python3 scripts/sync_public_aim.py --dest /path/to/hawikk/aim
    python3 scripts/sync_public_aim.py --dest /path/to/hawikk/aim --check
"""

from __future__ import annotations

import argparse
import fnmatch
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Files that are safe to publish and that this epic owns.
ALLOWLIST = [
    "CHANGELOG.md",
    "docs/README.md",
    "docs/start.md",
    "docs/trust.md",
    "docs/inventory.md",
    "docs/index.html",
    "docs/start.html",
    "docs/trust.html",
    "docs/inventory.html",
    "docs/self-host.html",
    "docs/pricing.md",
    "docs/pricing.html",
    "docs/changelog.html",
    "docs/.nojekyll",
    "docs/assets/site.css",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/inventory-gap.yml",
    ".github/ISSUE_TEMPLATE/collector-request.yml",
    "scripts/check_changelog.py",
    "scripts/cut_changelog.py",
    "scripts/test_changelog.py",
    "scripts/test_sync_public_aim.py",
    "scripts/check_docs_links.py",
    "scripts/sync_public_aim.py",
]

# Public copy retired by the AIM-1214 CEO record. Fail the overlay if these
# strings reappear in funnel files or the destination README.
RETIRED_COPY = (
    "soft fleet cap: 3 seats",
    "soft cap: 3 seats",
    "up to 5 seats",
    "$9 per user",
    "$9 / user",
)


# Refuse to copy, and fail --check, if the destination contains these.
DENY_GLOBS = [
    "docs/aim-*-pilot-evidence*",
    "docs/aim-*-fleet*",
    "docs/**/host-inventory*",
    "docs/privacy/dpia-pack/**",
    "docs/privacy/works-council-evidence-pack*/**",
    "docs/privacy/legal-templates/**",
    "docs/aim-110-shadow-report*",
    "docs/aim-113-blocklist-*/**",
    "docs/aim-115-pilot-evidence*",
    "docs/aim-292-product-evidence*",
    "docs/aim-571-fleet-mcp-deny-evidence*",
    "docs/collector-parity/**",
]


def _retired_hits(text: str) -> list[str]:
    lower = text.lower()
    return [phrase for phrase in RETIRED_COPY if phrase.lower() in lower]


def _denied(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    for glob in DENY_GLOBS:
        if fnmatch.fnmatch(rel, glob):
            return True
    return False


def overlay(dest: Path, check_only: bool) -> list[str]:
    errors: list[str] = []
    for rel in ALLOWLIST:
        src = REPO_ROOT / rel
        if not src.exists():
            errors.append(f"missing source {rel}")
            continue
        if src.suffix.lower() in {".md", ".html"}:
            retired = _retired_hits(src.read_text(errors="replace"))
            if retired:
                errors.append(f"retired public copy in source {rel}: {retired}")
        target = dest / rel
        if check_only:
            if not target.exists():
                errors.append(f"destination missing {rel}")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
    if check_only:
        for extra in ("README.md", "CONTRIBUTING.md"):
            extra_path = dest / extra
            if extra_path.is_file():
                retired = _retired_hits(extra_path.read_text(errors="replace"))
                if retired:
                    errors.append(
                        f"retired public copy in destination {extra}: {retired}"
                    )
    for path in dest.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(dest)).replace("\\", "/")
        if _denied(rel):
            errors.append(f"denylist hit in destination: {rel}")
    return errors


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dest", type=Path, required=True)
    p.add_argument("--check", action="store_true")
    args = p.parse_args(argv)
    dest = args.dest.resolve()
    if not dest.is_dir():
        print(f"destination is not a directory: {dest}", file=sys.stderr)
        return 2
    errs = overlay(dest, check_only=args.check)
    if errs:
        for e in errs:
            print(e, file=sys.stderr)
        return 1
    action = "checked" if args.check else "copied"
    print(f"OK {action} {len(ALLOWLIST)} funnel files → {dest}")
    print(
        "Checklist (still manual):\n"
        "  1. Do not rsync private docs/, deploy secrets, or ADRs.\n"
        "  2. Merge README / CONTRIBUTING by hand — they diverge on purpose.\n"
        "  3. Fix unpublished relative links (scripts/check_docs_links.py).\n"
        "  4. Open a PR on hawikk/aim; do not force-push main over community PRs.\n"
        "  5. After merge, confirm GitHub Pages source is main /docs."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
