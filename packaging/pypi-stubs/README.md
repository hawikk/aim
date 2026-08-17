# PyPI packaging notes (`aimonitoring-security`)

## Current state (accepted 2026-07-31)

**Product wheel** is published as [`aimonitoring-security`](https://pypi.org/project/aimonitoring-security/)
from the monorepo packaging path:

- Source of truth: `packaging/aim-cli/` + `scripts/build_aim_cli.py`
- Console script: `aim` (import package `aim`)
- Public install: `pipx install aimonitoring-security`
- CI publish paths:
  - **Canonical (tagged):** `.github/workflows/release-cli.yml` → GitHub Release + PyPI
  - **Emergency / OIDC-bound filename:** `.github/workflows/publish-pypi-stubs.yml`
    (filename frozen for the trusted-publisher binding created)

## Historical stub tree (`aimonitoring-security/` under this directory)

first claimed the name with version **0.0.1** and **no console scripts**
(name reservation only). That tree remains under
`packaging/pypi-stubs/aimonitoring-security/` for audit history; it is **not**
the product build path and must not be re-published as 0.0.1.

Charter names `aimonitoring` / `aim-monitoring` remain blocked by PyPI
similarity against third-party [`ai-monitoring`](https://pypi.org/project/ai-monitoring/)
(Whitecircle).
