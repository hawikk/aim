# aimonitoring-security (official name reservation)

**This PyPI project is an official name reservation by AI Monitoring.**

It is a deliberately empty stub (`0.0.1`): it contains **no product code** and
installs **no `aim` (or any other) console script**. Its only job is to hold
the `aimonitoring-security` name so lookalike packages cannot squat it.

The original short names `aimonitoring` / `aim-monitoring` cannot be claimed:
PyPI's similarity gate rejects them as too close to the unrelated existing
project [`ai-monitoring`](https://pypi.org/project/ai-monitoring/)
(Whitecircle). This package is the chosen alternate reservation.

## Do not use this package to install the CLI

The supported, trusted install path for the AI Monitoring endpoint agent is the
**signed wheel attached to a tagged GitHub Release** of
[`hawikk/aim`](https://github.com/hawikk/aim/releases):

```bash
# Example once a vX.Y.Z release exists (see the release notes for the exact URL
# and SHA256SUMS / cosign verification steps):
pipx install https://github.com/hawikk/aim/releases/download/vX.Y.Z/aim-X.Y.Z-py3-none-any.whl
```

PyPI is **not** a distribution channel for the product wheel. This stub exists
only so an official project name is owned by us and points back at that single
trust anchor.

## Why a non-empty stub?

PyPI's [PEP 541](https://peps.python.org/pep-0541/) policy forbids empty name
squatting. This package is an honest, installable reservation for a real,
forthcoming project whose supported distribution is GitHub Releases — not an
abandoned placeholder.
