"""Build the seeded repository the acceptance criteria are written
against: a historic leaked key, a committed `.env`, and an over-scoped PAT.

**No secret literal is committed to *this* repository.** Every credential below
is synthesized at run time from a fixed seed, so the fixture is byte-for-byte
reproducible without a single credential-shaped string living in AI Monitoring's
own git history. That matters for a reason beyond tidiness: a fixture built the
obvious way (paste a fake key into a file, add a `.gitleaks.toml` path
allowlist) blinds our own scanner to that directory forever, which is the exact
failure this pillar exists to catch in other people's repos.

The values are structurally valid — they match the issuer's real format, so the
upstream gitleaks rules fire on them — and they are not real credentials.

Two shapes are avoided on purpose:

* `AKIAIOSFODNN7EXAMPLE`, AWS's documented example key, is allowlisted by
  gitleaks' own default ruleset. A fixture built on it detects nothing and
  reports a confident zero (see `.gitleaks.toml`).
* Any value with real entropy from `secrets`/`os.urandom`. A fixture that
  differs per run cannot be asserted against.

Usage::

    python -m hygiene.demo.seed_repo /tmp/seeded-repo
"""

from __future__ import annotations

import os
import random
import subprocess
import sys

# Fixed seed → identical fixture on every machine and every CI run.
SEED = 20260726

# The commit that introduces the leak is dated well in the past so the report's
# "exposed for N days" figure is non-trivial and the ordering is deterministic.
LEAK_DATE = "2025-11-03T09:14:00+00:00"
ENV_DATE = "2026-02-17T16:40:00+00:00"
HEAD_DATE = "2026-07-20T11:05:00+00:00"


def _rng() -> random.Random:
    return random.Random(SEED)


def synth() -> dict[str, str]:
    """Structurally valid, deterministically fake credentials.

    Each format below is the one the corresponding upstream gitleaks rule
    matches: AWS access key ids are `(AKIA|ASIA|…)` + 16 upper alnum, classic
    GitHub PATs are `ghp_` + 36 base62, Slack bot tokens are `xoxb-` + numeric
    triplets. Getting these wrong produces a fixture that silently finds nothing.
    """
    rng = _rng()
    # AWS access key ids are base32 after the prefix — [A-Z2-7], with no
    # 0/1/8/9. This is not cosmetic. gitleaks' `aws-access-token` rule encodes
    # the real alphabet, so a key drawn from [A-Z0-9] (the obvious choice) is
    # NOT matched by it; it falls through to `generic-api-key` instead. The
    # fixture still "finds a secret", which is why this is easy to miss — but
    # the rule id is the join key for issuer routing, so the finding would get
    # the generic remediation with no AWS console URL, no rotation CLI, and no
    # `sts:GetCallerIdentity` liveness probe. The critical-alert acceptance
    # path would go quietly dead. Verified against gitleaks 8.28.0.
    aws_b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    b62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b64 = b62 + "+/"
    return {
        # The historic leak: committed in 2025, deleted in 2026, still live.
        "aws_key_id": "AKIA" + "".join(rng.choice(aws_b32) for _ in range(16)),
        "aws_secret": "".join(rng.choice(b64) for _ in range(40)),
        # The over-scoped PAT, committed in `.env` and never removed.
        "github_pat": "ghp_" + "".join(rng.choice(b62) for _ in range(36)),
        "slack_token": ("xoxb-" + "".join(rng.choice("0123456789") for _ in range(12))
                        + "-" + "".join(rng.choice("0123456789") for _ in range(13))
                        + "-" + "".join(rng.choice(b62) for _ in range(24))),
        "pg_password": "".join(rng.choice(b62) for _ in range(18)),
    }


def _git(repo: str, *args: str, when: str = "") -> None:
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_NAME": "Seed Fixture", "GIT_AUTHOR_EMAIL": "seed@example.invalid",
        "GIT_COMMITTER_NAME": "Seed Fixture", "GIT_COMMITTER_EMAIL": "seed@example.invalid",
        # A fixed identity and clock make commit shas stable across runs, which
        # is what lets a test assert on a specific commit.
        "GIT_AUTHOR_DATE": when or HEAD_DATE, "GIT_COMMITTER_DATE": when or HEAD_DATE,
    })
    subprocess.run(["git", *args], cwd=repo, env=env, check=True,
                   capture_output=True, text=True)


def _write(repo: str, path: str, text: str) -> None:
    full = os.path.join(repo, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(text)


def build(repo: str) -> dict[str, str]:
    """Create the fixture repo at `repo`. Returns the synthesized values so a
    test can assert on their fingerprints without re-deriving them."""
    creds = synth()
    os.makedirs(repo, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "seed@example.invalid")
    _git(repo, "config", "user.name", "Seed Fixture")
    _git(repo, "config", "commit.gpgsign", "false")

    # ---- commit 1: the leak enters history -------------------------------
    # A deploy script with the key inline. This is the classic shape: someone
    # hardcodes it "just to get the deploy working" and it is never cleaned up.
    _write(repo, "deploy/push.sh",
           "#!/usr/bin/env bash\n"
           "set -euo pipefail\n"
           "# TODO: move these to the secret store before we ship\n"
           f"export AWS_ACCESS_KEY_ID={creds['aws_key_id']}\n"
           f"export AWS_SECRET_ACCESS_KEY={creds['aws_secret']}\n"
           "aws s3 sync ./dist s3://acme-releases/\n")
    _write(repo, "README.md", "# acme-service\n\nInternal release tooling.\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "deploy: add release push script", when=LEAK_DATE)

    # ---- commit 2: the leak is 'fixed' by deleting the line --------------
    # This is the commit that makes the pillar necessary. After it, a worktree
    # scan (what gatehouse runs on a PR) reports zero. The credential is still
    # recoverable by anyone who can clone, and is still live until rotated.
    _write(repo, "deploy/push.sh",
           "#!/usr/bin/env bash\n"
           "set -euo pipefail\n"
           "# creds now come from the CI environment\n"
           "aws s3 sync ./dist s3://acme-releases/\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "deploy: stop hardcoding AWS creds", when="2026-01-08T10:22:00+00:00")

    # ---- commit 3: a committed .env, plus config with inline creds -------
    # `.gitignore` exists but does not cover `.env` — the specific gap check 2
    # looks for. It covers node_modules only, which is what makes it look
    # cared-for at a glance.
    _write(repo, ".gitignore", "node_modules/\ndist/\n*.log\n")
    _write(repo, ".env",
           "NODE_ENV=production\n"
           f"GITHUB_TOKEN={creds['github_pat']}\n"
           f"SLACK_BOT_TOKEN={creds['slack_token']}\n"
           "FEATURE_FLAGS=beta\n")
    _write(repo, "config/database.yml",
           "production:\n"
           "  adapter: postgresql\n"
           "  host: db.internal.acme.example\n"
           f"  url: postgres://acme_app:{creds['pg_password']}@db.internal.acme.example:5432/acme\n")
    _write(repo, ".env.example",
           "NODE_ENV=production\nGITHUB_TOKEN=\nSLACK_BOT_TOKEN=\nFEATURE_FLAGS=\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "chore: add local env and db config", when=ENV_DATE)

    # ---- commit 4: ordinary work on top ----------------------------------
    # So the leak is not the tip commit; a scan that only looks at HEAD misses it.
    _write(repo, "src/index.js", "export const version = '1.4.2';\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "release 1.4.2", when=HEAD_DATE)
    return creds


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    target = os.path.abspath(argv[1])
    if os.path.exists(os.path.join(target, ".git")):
        print(f"{target} is already a git repo; refusing to overwrite", file=sys.stderr)
        return 1
    build(target)
    print(f"seeded fixture repo at {target}")
    print("expected: 1 historic AWS key (deleted from the worktree, live in history),")
    print("          1 committed .env holding an over-scoped PAT + Slack token,")
    print("          1 config file with an inline database password,")
    print("          .gitignore present but missing .env")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
