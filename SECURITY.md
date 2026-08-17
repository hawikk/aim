# Security Policy

AIM is a security product, so the bar for this repo is higher than average.
Please report vulnerabilities privately.

## Reporting a vulnerability

Email **[security@getaimonitoring.com](mailto:security@getaimonitoring.com)**
with the subject prefix `Security` and include:

- affected component and the commit SHA you tested,
- reproduction steps or a proof of concept,
- suspected impact and any preconditions (network position, privileges, config).

Do not open a public GitHub issue, pull request, or discussion for an unfixed
vulnerability, and do not post details on social media before a fix is out.

If you need to encrypt the report, say so in a first plaintext email and we
will arrange a key.

## What to expect

This repository is maintained by a single developer, so the timelines below are
best effort rather than a contractual SLA:

- **Acknowledgement** — typically within a few days.
- **Triage and severity assessment** — typically within a week of
  acknowledgement, alongside a rough fix estimate.
- **Progress updates** — roughly every two weeks while an issue is open.

If you have not heard back within two weeks, please send a follow-up. Mail does
get lost, and a nudge is always welcome rather than an imposition.

## Coordinated disclosure

We ask for a **90-day** disclosure window from the date we acknowledge your
report, extended only by mutual agreement if a fix is genuinely complex. If we
ship a fix sooner, we are happy to publish sooner.

We will credit reporters by name or handle in the release notes unless you ask
us not to. There is no bug bounty and no monetary reward — this is an
unfunded open-source project, and we would rather be upfront about that than
imply otherwise.

## Scope

**In scope** — anything in this repository: the endpoint collectors
(`collectors/`), the services (`services/`), the ingest and API layers
(`apps/api`, `services/ingest`), the analyst dashboard (`apps/web`), the
packaged `aim` CLI (`packaging/aim-cli`), the deployment manifests
(`deploy/`, `infra/`, `docker-compose.yml`), and the canonical event schemas
(`packages/schema`).

Findings we are particularly interested in: anything that causes AIM to
collect or transmit prompt content, source code, or plaintext identities;
authentication or tenant-isolation bypasses in the API; guardrail or
enforcement decisions that can be silently evaded; and insecure defaults in the
shipped compose or Helm manifests.

**Out of scope** — the marketing site at `getaimonitoring.com` (report those to
the same address, but they are not tracked as product vulnerabilities), findings
that require a fully compromised endpoint or root on the host AIM runs on,
missing hardening headers with no demonstrated impact, automated scanner output
with no working proof of concept, and vulnerabilities in third-party
dependencies that have no exploitable path through AIM (please report those
upstream).

## Supported versions

This repository is a public snapshot of a larger internal codebase and has **no
tagged releases yet**. Only the current `main` branch is supported. Fixes land
on `main`; there are no backports to older commits. Once releases are tagged,
this section will state a support window.

## Defaults enforced in this repo

- **Secret scanning** — `.githooks/pre-commit` runs
  `gitleaks protect --staged` against `.gitleaks.toml`. The hook is opt-in
  (`git config core.hooksPath .githooks`, done by `make setup`) and skips with
  a warning if `gitleaks` is not installed locally.
- **No secrets committed** — `.env` and `*.tfvars` are gitignored; only
  `*.example` templates are committed.
- **Metadata-only by default** — the canonical event schema in
  `packages/schema` rejects prompt text, response bodies, message content, and
  tool-call arguments outright, and rejects plaintext identities in favour of
  hashes. `python3 packages/schema/validate.py` exercises this against a corpus
  of deliberately invalid events and runs in CI.
