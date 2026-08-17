# `aim` — one installable artifact

The packaged AI Monitoring CLI. One versioned wheel bundles every endpoint
collector (Claude Code, Cursor, Kilo Code, Kimi Code) and the local dashboard
behind a single `aim` command, so an engineer can install it with `pipx` and
run `aim personal` — no repo clone, no `cd` into subdirectories, no
infrastructure.

This is the foundation of the magic-install epic (AIM-129); the rest of that
epic's children hang off this artifact.

## Install

Distribution name is **`aimonitoring-security`** (D-489-3);
console script and import package remain **`aim`**. Do **not**
`pipx install aim` — that PyPI name is AimStack's unrelated tracker.

Package install is a versioned wheel/sdist (reproducible, auditable). For fleet
pilot enroll only, the dashboard also hosts a one-shot helper
(`http://<aim-host>:8081/enroll.sh`, AIM-1124) that installs this package via
pipx, then runs `aim join` + `aim doctor --fix` and fails closed if
`token_file` is missing. Prefer the wheel path for air-gapped mirrors.

### Public (preferred)

```sh
pipx install aimonitoring-security
aim personal
aim --version
```

### Signed GitHub Release (offline / private-repo mirror)

CI-built wheel + `SHA256SUMS` + keyless cosign (identity =
`.github/workflows/release-cli.yml` at the tag):

```sh
TAG=v0.1.1
REPO=hawikk/aim
WHEEL=aimonitoring_security-${TAG#v}-py3-none-any.whl

gh release download "$TAG" -R "$REPO" \
  -p "$WHEEL" -p "SHA256SUMS" -p "${WHEEL}.sigstore"

sha256sum -c SHA256SUMS --ignore-missing
cosign verify-blob --bundle "${WHEEL}.sigstore" \
  --certificate-identity-regexp "^https://github.com/${REPO}/\\.github/workflows/release-cli\\.yml@" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$WHEEL"

pipx install "./$WHEEL"      # recommended (isolated)
# or: pip install "./$WHEEL"
```

**Requires Python 3.11+.** Packaging metadata (`requires-python = ">=3.11"`)
refuses install on older interpreters; an import/CLI guard fails fast with a
human message and a link to the install docs if an old interpreter somehow
still loads the package.

Runtime dependencies: **none**. The collectors are stdlib-only by contract,
and this package adds nothing — installing the wheel pulls no transitive deps.

## Use

### Individual mode — monitor your own AI usage, zero infra

```sh
aim personal          # scan your local AI-tool data into SQLite and serve the
                      # dashboard on http://127.0.0.1:8787 — zero outbound calls
aim personal --watch  # keep rescanning while the dashboard is up
aim personal --port 9000
aim version           # CLI + bundled collector versions
```

`aim personal` binds **127.0.0.1 only** and makes **zero outbound network
calls**. Content (prompts/responses) is matched for secrets/PII in memory and
discarded immediately — only detector *names* and usage metadata are stored,
in a local SQLite file under `~/.aim-collector/`.

### Fleet mode — one line hooks + enrolls every installed tool (AIM-138)

```sh
aim join <ingest-url> --token <enroll-token>   # detect → hook → enroll → verify
aim status                                     # per-tool hook / enroll / heartbeat / spool
aim uninstall                                  # unhook every tool + remove all state
```

Private CA / split-horizon (AIM-238) — needed when the stack gateway serves
Caddy's internal CA, or when `ingest.localhost` does not resolve on the host:

```sh
aim join https://ingest.localhost:8443 --token <enroll-token> \
  --ca-bundle secrets/stack-ca.crt \
  --resolve ingest.localhost:8443:127.0.0.1
```

`--ca-bundle` (alias `--ca-cert`) and `--resolve host:port:ip` are persisted
into the per-user `config.json` so the watch daemon reuses them without
ambient `SSL_CERT_FILE`. `SSL_CERT_FILE` / `AIM_CA_BUNDLE` / `AIM_RESOLVE`
are still honoured when set.

`aim join` is the enterprise-engineer magic moment: it detects which supported
AI tools are present on the machine, registers the collector hook for the
hook-capable ones (Claude Code, Cursor), configures the scan-based ones (Kilo
Code, Kimi Code), enrolls the device **once**, and verifies connectivity with a
first heartbeat. Tools that aren't installed are reported as *skipped*, not
errors. It prints a per-tool summary and is **idempotent** — re-running repairs
or refreshes rather than duplicating hooks.

Ordering is a security property: enrollment (which validates the token against
the ingest endpoint) happens **before any hook is written**, so a wrong or
revoked token fails fast and leaves **no partial hooks** behind. One physical
machine stays **one device** — Claude/Kilo/Kimi share a state dir, and Cursor's
separate state dir is bridged onto the same device identity.

`aim status` is read-only (no network): it reports, per installed tool, whether
the hook is registered (or scan-based), enrollment state, last heartbeat age,
and local spool depth — exiting non-zero when an installed tool is unhooked or
the device is not enrolled, so it doubles as a health check.

> Local end-to-end drive without the real ingest service:
> `python3 scripts/aim-138-stub-ingest.py 8799` then
> `aim join http://127.0.0.1:8799 --token demo`.

## Build the artifact (developers / air-gapped mirrors)

Personal-mode users should install from the GitHub Release, not from a local
build. This section is for developers and IT admins who need to rebuild.

One command, standard library only — builds on a bare Python with no pip, no
setuptools, no network (so an IT admin can produce the mirror artifact on an
air-gapped box):

```sh
python3 scripts/build_aim_cli.py      # or: make aim-cli
```

Outputs to `packaging/aim-cli/dist/`:

- `aimonitoring_security-<version>-py3-none-any.whl` — the install artifact
- `aimonitoring_security-<version>.tar.gz` — auditable source archive (sdist)

The version in `pyproject.toml` (kept in lockstep with `src/aim/__init__.py`)
is the single source of truth; it is embedded in the wheel and reported by
`aim version` / `aim --version`. Builds are deterministic — the same source
yields a byte-identical wheel (verify with `sha256sum`).

Tagged releases (`v*`) run `.github/workflows/release-cli.yml`, which builds
these artifacts on CI, writes `SHA256SUMS`, cosign-signs each blob keylessly,
attaches everything to the GitHub Release, publishes the same wheel to PyPI as
`aimonitoring-security`, and post-verifies install + `aim --version` against
the tag. **Do not hand-upload release assets.**
### How the bundle is laid out

The build vendors the collector source **verbatim** (no binaries) into
`src/aim/_vendor/`, preserving the monorepo-relative layout the collectors
already walk up to discover:

```
aim/_vendor/
  collectors/{claude-code,cursor,kilo-code,kimi-code,grok-build,github-copilot}/<pkg>/...
  apps/web/public/...          # the dashboard, served as static files
```

Because the relative shape is preserved, the collector code runs byte-for-byte
unchanged whether it's a git clone or an installed wheel — no import shims. The
`_vendor/` tree is build output (git-ignored); it is regenerated on every build
and must never be hand-edited.

## Security posture

Aligned with the epic's binding security bar:

- **Versioned, file-auditable wheel/sdist** as the install artifact (reproducible
  build). The optional dashboard `enroll.sh` one-shot (AIM-1124) wraps pipx +
  `aim join` for pilot UX; it never logs the enrollment token and fails closed
  without `token_file`.
- **Stdlib-only runtime**, unchanged from the collectors.
- **No vendored binaries** — only readable Python + static web assets.
- **Least privilege / blast radius:** everything is per-user, never root.
  `aim personal` is loopback-only, zero egress; `aim join` writes only
  user-scoped hooks + config (never `/etc` or `%ProgramData%`).
- **Fail-fast, no partial state:** `aim join` enrolls before hooking, so a
  bad/revoked token leaves nothing behind.
- **Clean uninstall:** `aim uninstall` unhooks every tool, clears the device
  identity, and removes all state aim wrote; it is idempotent and never
  touches a settings file it didn't contribute to.
