"""Overlay allowlist and retired public-copy scan (AIM-1212 / AIM-1214)."""

from pathlib import Path

import sync_public_aim as sync

ROOT = Path(__file__).resolve().parent.parent


def test_pricing_pages_are_on_the_overlay():
    assert "docs/pricing.md" in sync.ALLOWLIST
    assert "docs/pricing.html" in sync.ALLOWLIST
    for rel in sync.ALLOWLIST:
        assert (ROOT / rel).is_file(), rel


def test_source_overlay_has_no_retired_seat_copy():
    hits = []
    for rel in sync.ALLOWLIST:
        path = ROOT / rel
        if path.suffix.lower() not in {".md", ".html"}:
            continue
        found = sync._retired_hits(path.read_text(errors="replace"))
        if found:
            hits.append((rel, found))
    assert hits == [], hits


def test_repo_front_door_has_no_retired_seat_copy():
    hits = []
    for name in ("README.md", "CONTRIBUTING.md"):
        path = ROOT / name
        if not path.is_file():
            continue
        found = sync._retired_hits(path.read_text(errors="replace"))
        if found:
            hits.append((name, found))
    assert hits == [], hits


def test_retired_copy_matches_the_ceo_record():
    text = "Community (free, soft cap: 3 seats) | Clone this repo"
    assert "soft cap: 3 seats" in sync._retired_hits(text)
    assert not sync._retired_hits("Community is free and uncapped")
    # Demo fixture size is not a license line.
    assert not sync._retired_hits("A deterministic 12-seat demo cohort")
