# Contributing to AIM

Thanks for looking at this. Before you invest time, please read the next
paragraph — it will save you some.

## What this repository is

This is a **public Apache-2.0 snapshot of a larger internal monorepo**,
maintained by one developer. Most code here is written and reviewed upstream
and then exported, which has two consequences worth knowing:

- **Some things are missing.** The per-collector and per-service `tests/`
  directories are not part of this snapshot, so `pytest` at the root will only
  find the suites under `scripts/`. Likewise there is no internal CI tooling,
  no self-hosted runner config, and no release automation here.
- **Merges can be slow, and some are impossible as-written.** A change to a
  collector or service may need to be re-applied upstream by hand rather than
  merged directly. If that happens you will be told, and you will be credited.

Response times are best effort: **expect a few days for a first reply, and
sometimes a couple of weeks for a full review.** There is no team behind this
and no on-call rotation. A polite nudge on a stale thread is welcome.

There is no published roadmap and no governance process. Decisions are made by
the maintainer. Please be civil and assume good faith; that is the whole code
of conduct, and the maintainer is the only person who enforces it.

## Before you start

**Open an issue first for anything non-trivial.** A bug fix or a docs
correction can go straight to a pull request. A new collector, a schema change,
or anything that alters what data leaves an endpoint should start as an issue,
so we can agree on the approach before you write it.

Changes that would cause AIM to collect prompt text, source code, file
contents, or plaintext identities will not be accepted. Metadata-only is the
product's core promise and the canonical schema in `packages/schema` enforces
it.

## Setting up a dev environment

You need **Python 3.11+** (CI uses 3.12) and **Node 22** (see `.nvmrc`).
Docker is only needed to actually run the stack, not to run the checks below.

```bash
git clone https://github.com/hawikk/aim.git
cd aim

# Python. The CI checks need only these three; requirements-dev.txt is the
# fuller list and also installs the services as editable packages.
python3 -m venv .venv
. .venv/bin/activate
pip install 'pytest>=8.0' 'jsonschema>=4.20' 'PyYAML>=6.0'
# ...or, for the full set:  pip install -r requirements-dev.txt

# Node. pnpm 9 is the declared package manager (pinned in package.json).
corepack enable
pnpm install --frozen-lockfile
```

`make setup` does the `pnpm install` for you and additionally points
`core.hooksPath` at `.githooks`, which enables the gitleaks pre-commit scan.
Install [gitleaks](https://github.com/gitleaks/gitleaks) as well, or the hook
will skip itself with a warning.

To run the product locally: `./scripts/demo-stack-up.sh` (needs Docker), then
open `http://127.0.0.1:8081`.

## Running the checks

These are exactly the steps in `.github/workflows/ci.yml`, in the same order.
All of them run offline and none need Docker, a database, or credentials.

```bash
# Python job
python -m pytest scripts -q
python packages/schema/validate.py
python scripts/build_aim_cli.py
python scripts/validate_mcp_threat_catalogue.py
python scripts/check_tool_version_matrix.py
python scripts/check_os_install_enroll_matrix.py
python scripts/check_provider_catalogue_drift.py

# Node job
pnpm lint
pnpm typecheck
node --test scripts/test_compose_bind.mjs
node --test scripts/test_compose_pull.mjs
```

Note that **`pnpm test` does not work in this snapshot** and is deliberately
not in CI: `services/ingest` runs `vitest run`, the workspace test files are
not part of the public export, and vitest exits non-zero when it finds none.

`scripts/build_aim_cli.py` writes into `packaging/aim-cli/dist/` and
`packaging/aim-cli/src/aim/_vendor/`. Both are gitignored — do not commit them.

Green CI is necessary but not sufficient: the suites in this snapshot cover the
event schema, the packaging path, the compose contracts and the guardrail
matrices, but **not** the collectors or the services. If you change those, say
in the pull request how you tested them.

## Code style

- **`.editorconfig` is the baseline** — UTF-8, LF, two-space indent, final
  newline, no trailing whitespace. Most editors pick this up automatically.
- **JavaScript and TypeScript** must pass `pnpm lint` (`eslint .`) and
  `pnpm typecheck` with no errors. The flat config is `eslint.config.js`.
  Prefix intentionally-unused bindings with an underscore rather than
  disabling the rule.
- **Python** has no enforced formatter or linter in this repo. Match the
  surrounding code: standard-library-only in `collectors/` (that is a hard
  contract — the shipped wheel has zero runtime dependencies), type hints on
  new functions, and a module docstring saying what the file is for.
- **Comments** should explain intent or a constraint, not restate the code.
  A comment that records why a constraint exists is worth keeping even when
  it is long; one that restates the next line is not.

Do not add runtime dependencies without discussing it in an issue first.

## Commits and pull requests

This repository is a curated snapshot, so its history is shorter than the
development history behind it. For contributions here:

- Write a short imperative subject line, ideally under ~70 characters, e.g.
  `fix cursor collector crash on empty state.vscdb`.
- Reference the GitHub issue in the body (`Closes #12`) rather than the subject.
- Keep one logical change per pull request. Unrelated drive-by reformatting
  makes review much slower and is the most common reason a PR stalls.
- Rebase rather than merge `main` into your branch, so history stays linear.

A useful pull-request description answers four things — what changed, why, how
to verify it, and what the security or privacy impact is. That last one is not
boilerplate for this project: state what data the change collects, stores, or
exposes, or write "none".

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), same as the rest of the repository.

## Where to ask questions

- **Bugs, features, and general questions** — open a
  [GitHub issue](https://github.com/hawikk/aim/issues). Discussions are not
  enabled, so issues are the right place even for open-ended questions.
- **Security vulnerabilities** — do **not** open an issue. Email
  [security@getaimonitoring.com](mailto:security@getaimonitoring.com); see
  [SECURITY.md](SECURITY.md) for what to include and what to expect.
- **Commercial questions** (Team/Enterprise tiers, SSO, evidence packs) —
  [sales@getaimonitoring.com](mailto:sales@getaimonitoring.com).
