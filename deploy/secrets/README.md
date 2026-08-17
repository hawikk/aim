# Local secrets (git-ignored)

`gatehouse-app.pem` — the GitHub App private key gatehouse uses to mint
repo-scoped installation tokens. Download it from the App's settings page and
drop it here, or point `GATEHOUSE_PRIVATE_KEY_HOST_PATH` somewhere else.

A file rather than an environment variable on purpose: env vars appear in
`docker inspect` and are inherited by every scanner subprocess gatehouse runs
over untrusted repository code.

`GATEHOUSE_REVERT_TOKEN` and `GATEHOUSE_GITHUB_TOKEN` are **not** files in this
directory. They live in the stack `.env` (mode 0600) and are injected into the
`gatehouse` / `gatehouse-merge-audit` services. See
`docs/security/gatehouse-pat-cutover.md` (consumer inventory + cutover/rollback)
and `docs/security/enforcing-ci-gates.md` § Auto-revert token for mint + rotation.
Never paste those values into this README or any committed file.

Nothing in this directory except this README is committed — see `.gitignore`.
