"""Overlay allowlist and retired public-copy scan (AIM-1212 / AIM-1214)."""

from pathlib import Path

import sync_public_aim as sync

ROOT = Path(__file__).resolve().parent.parent


def test_pricing_pages_are_on_the_overlay():
    assert "docs.pricing.md" in sync.ALLOWLIST
