# Changelog

All notable changes to the published `aim` CLI (`aimonitoring-security` on
PyPI) and the public Community snapshot are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates for 0.1.1–0.1.4 are PyPI upload times. Tag messages and commit subjects
are taken from the public `hawikk/aim` history and the private release tags —
do not read this file as a promise of features that were not in those notes.

## [Unreleased]

## [0.1.4] - 2026-08-18

Public Community snapshot of AI Monitoring under Apache-2.0. Endpoint
blocking where vendor hooks exist.

PyPI: `aimonitoring-security==0.1.4` (uploaded 2026-08-18). Public tag
`v0.1.4` on [hawikk/aim](https://github.com/hawikk/aim) (annotated tag
message: *aimonitoring-security 0.1.4 — endpoint blocking for Cursor,
Copilot, Kimi, Grok*). Public commit subject: *Ship 0.1.4 with endpoint
blocking for Cursor, Copilot, Kimi, and Grok.*

### Added

- Endpoint blocking matrix where hooks exist: Cursor, GitHub Copilot, Kimi
  Code, and Grok Build can actuate on the endpoint when a managed
  `enforcement.json` is loaded. Grok Build denies **tool calls** only
  (`PreToolUse`). Copilot CLI does not block the initial prompt (GitHub
  drops command-hook output on `userPromptSubmitted`).
- Public Community snapshot of the working tree on `hawikk/aim` (first
  public commit 2026-08-17; this tag is that snapshot as of 2026-08-18).

### Changed

- Published wheel license: **Proprietary** on 0.1.1–0.1.3 PyPI metadata →
  **Apache-2.0** on 0.1.4. Relicensing landed on the public snapshot
  between the first public wheel and this tag.

## [0.1.3] - 2026-08-17

PyPI: `aimonitoring-security==0.1.3` (uploaded 2026-08-17). Public commit
subject: *Ship 0.1.3 with an honest personal-mode tool list and a markdown
PyPI description.*

### Changed

- Personal-mode tool list matches what the wheel actually scans (Claude
  Code, Cursor, Kilo Code, Kimi Code, Grok Build, GitHub Copilot) rather
  than an over-claim.
- PyPI long description is markdown (`text/markdown`).

## [0.1.2] - 2026-08-17

PyPI: `aimonitoring-security==0.1.2` (uploaded 2026-08-17). Public commit
subject: *Cut 0.1.2 so the published package points somewhere that exists*.

### Fixed

- Project URLs on the published package point at
  `https://github.com/hawikk/aim`, a repository that exists.

## [0.1.1] - 2026-07-31

First public product wheel. PyPI: `aimonitoring-security==0.1.1` (uploaded
2026-07-31). Private annotated tag `v0.1.1`: *aim CLI 0.1.1 —
aimonitoring-security on PyPI*. This version is **not** tagged on
`hawikk/aim` (the public tree starts later).

### Added

- First public `aimonitoring-security` wheel with console script `aim`.
  Stdlib-only runtime. Install: `pipx install aimonitoring-security`.
- `aim personal` — local dashboard on `127.0.0.1`, zero outbound network
  calls.

### Notes

- PyPI license classifier on this wheel: Proprietary. Apache-2.0 lands
  on 0.1.4 (see above).
- `0.0.1` (same day) was a PyPI name-reservation stub with no `aim`
  console script. It is not a product release and is not listed as one.

[Unreleased]: https://github.com/hawikk/aim/compare/v0.1.4...HEAD
[0.1.4]: https://pypi.org/project/aimonitoring-security/0.1.4/
[0.1.3]: https://pypi.org/project/aimonitoring-security/0.1.3/
[0.1.2]: https://pypi.org/project/aimonitoring-security/0.1.2/
[0.1.1]: https://pypi.org/project/aimonitoring-security/0.1.1/
