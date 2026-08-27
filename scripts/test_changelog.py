"""Keep-a-Changelog helpers used by release CI and the public snapshot."""

from pathlib import Path

from check_changelog import check, headings, self_test
from cut_changelog import cut

SAMPLE = """# Changelog
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- docs site

## [0.1.4] - 2026-08-18

## [0.1.3] - 2026-08-17

## [0.1.2] - 2026-08-17

## [0.1.1] - 2026-07-31

[Unreleased]: https://github.com/hawikk/aim/compare/v0.1.4...HEAD
"""


def test_required_releases_present_on_repo_changelog():
    text = Path(__file__).resolve().parent.parent.joinpath("CHANGELOG.md").read_text()
    errs = check(text)
    assert errs == [], errs
    names = [n for n, _ in headings(text)]
    assert names[0] == "Unreleased"


def test_cut_moves_unreleased_body():
    out = cut(SAMPLE, "0.1.5", "2026-08-27", allow_empty=False)
    assert "## [0.1.5] - 2026-08-27" in out
    assert "- docs site" in out.split("## [0.1.5]")[1].split("## [0.1.4]")[0]
    assert "[Unreleased]: https://github.com/hawikk/aim/compare/v0.1.5...HEAD" in out
    assert check(out, version="0.1.5") == []


def test_check_changelog_self_test():
    assert self_test() == 0
