"""Ephemeral repo checkouts. The code is a temporary, the finding is the record.

Acceptance criterion: "repo contents are scanned in ephemeral workspaces and
deleted after the run". Three things make that true here rather than aspirational:

1. The workspace is a context manager whose `finally` removes the tree, so an
   exception in a scanner cannot leave source on disk.
2. Removal is *verified* and logged (`gatehouse.workspace.removed`), because a
   cleanup that silently failed is exactly the kind of quiet gap this product
   exists to catch.
3. The clone is `--filter=blob:none`: gatehouse fetches commit history but only
   the blobs it actually checks out. Less code on disk, and a faster clone.

The installation token never reaches argv or `.git/config`. It is handed to git
through GIT_ASKPASS, so `ps` on a shared host does not show it and a leftover
config file (there should not be one) does not contain it.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from typing import Iterator

GIT_TIMEOUT = int(os.environ.get("GATEHOUSE_GIT_TIMEOUT", "120"))

_ASKPASS = '#!/bin/sh\nprintf "%s" "$GATEHOUSE_GIT_TOKEN"\n'


class WorkspaceError(RuntimeError):
    """Clone/fetch failed. Fatal for the run — a partial checkout must not be
    scanned and reported as clean."""


def _log(payload: dict) -> None:
    print(json.dumps(payload), file=sys.stderr, flush=True)


def git(args: list[str], *, cwd: str, env: dict | None = None, check: bool = True):
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT,
    )
    if check and proc.returncode != 0:
        # git puts the remote URL in some error messages; the URL never carries
        # the token (see module docstring), so this is safe to surface.
        raise WorkspaceError(f"git {args[0]} failed ({proc.returncode}): {proc.stderr.strip()[:400]}")
    return proc


@contextmanager
def ephemeral_checkout(
    repo_full_name: str,
    *,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    token: str = "",
    api_host: str = "github.com",
    root: str | None = None,
) -> Iterator[str]:
    """Clone the PR head into a temp dir, yield the path, always delete it.

    Fetches `refs/pull/N/head` rather than the head repository, which is what
    makes fork PRs work with a single installation token scoped to the base
    repo — and is why gatehouse never needs credentials for the fork.
    """
    workdir = tempfile.mkdtemp(prefix="gatehouse-", dir=root)
    try:
        env = dict(os.environ)
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        if token:
            askpass = os.path.join(workdir, ".askpass")
            with open(askpass, "w") as fh:
                fh.write(_ASKPASS)
            os.chmod(askpass, stat.S_IRWXU)
            env["GIT_ASKPASS"] = askpass
            env["GATEHOUSE_GIT_TOKEN"] = token

        repo_dir = os.path.join(workdir, "repo")
        os.makedirs(repo_dir)
        url = f"https://x-access-token@{api_host}/{repo_full_name}.git"
        git(["init", "--quiet", "-b", "gatehouse-scan"], cwd=repo_dir, env=env)
        git(["remote", "add", "origin", url], cwd=repo_dir, env=env)
        # Commits + trees, no blobs: enough for merge-base and rename detection.
        git(
            ["-c", "protocol.version=2", "fetch", "--quiet", "--filter=blob:none",
             "--no-tags", "origin", f"+refs/pull/{pr_number}/head:refs/gatehouse/head",
             f"+{base_sha}:refs/gatehouse/base"],
            cwd=repo_dir, env=env,
        )
        # Detached checkout of the head. Blobs arrive on demand from the
        # promisor remote, so only files that exist at head land on disk.
        git(["checkout", "--quiet", "--detach", "refs/gatehouse/head"], cwd=repo_dir, env=env)
        actual = git(["rev-parse", "HEAD"], cwd=repo_dir, env=env).stdout.strip()
        if head_sha and not actual.startswith(head_sha[:7]):
            # The PR was re-pushed between the webhook and the clone. Scanning
            # a different commit than the one we will report on would attach
            # annotations to the wrong lines, so stop and let the newer
            # `synchronize` event drive its own run.
            raise WorkspaceError(
                f"head moved during checkout: expected {head_sha[:12]}, got {actual[:12]}")
        yield repo_dir
    finally:
        # Drop the token before the tree goes, so a slow rmtree cannot be
        # interrupted with the askpass script still readable.
        askpass = os.path.join(workdir, ".askpass")
        if os.path.exists(askpass):
            os.remove(askpass)
        shutil.rmtree(workdir, ignore_errors=True)
        _log({
            "event": "gatehouse.workspace.removed",
            "workdir": workdir,
            "gone": not os.path.exists(workdir),
        })
        if os.path.exists(workdir):
            # Loud, not fatal: the scan already produced findings and dropping
            # them helps nobody, but source code left on disk is an incident.
            _log({"event": "gatehouse.workspace.cleanup_failed", "workdir": workdir})
