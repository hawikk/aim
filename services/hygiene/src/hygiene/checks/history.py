"""Check 1 — every secret that ever reached this repo's history.

The distinction from pillar 3 (gatehouse) is the entire point of this check and
is worth stating plainly, because "we already run gitleaks" is the objection
this pillar will get in every review:

    gatehouse runs gitleaks over a PR's *worktree*. It answers "does this pull
    request ADD a secret?" and it must, because re-reporting every historic
    leak on every PR is how a gate gets ignored.

    This check runs `gitleaks git` over the full object graph. It answers "what
    is still recoverable from this repo?" — which, for a secret deleted in a
    later commit, is a completely different answer.

Measured on `demo/seed_repo.py`, where an AWS key was committed and then removed
two commits later: worktree mode reports 2 findings and misses the AWS key
entirely; history mode reports 4 and finds it at the commit that introduced it.
That credential is live until someone rotates it. The file being gone changes
nothing.

**Why liveness verification happens in here.** Probing an issuer needs the raw
credential, and `Finding` deliberately has no field one fits in. Rather than
return raw values to a caller — which would put a secret in a variable
somewhere up the stack, forever, waiting to be logged — this module takes an
injected `verify` callable and does the probing while the value is still in
local scope. Raw secrets exist inside `scan()` and nowhere else in the service.

**Handling of the report file.** gitleaks writes matched secrets to its JSON
report in the clear; there is no mode in which it does not. We write that report
to a 0700 directory outside the repository — so a worktree scan or a `git add
-A` can never pick it up — parse it, and unlink it in a `finally`.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Callable

from .. import remediation
from ..models import Finding, fingerprint, mask, safe_label
from . import liveness

FINDING_TYPE = "secrets_hygiene.leaked_credential"

# gitleaks exits 1 when it finds leaks; that is a successful scan for us.
_OK = (0, 1)

# An AWS secret access key: exactly 40 characters of base64. It has no prefix
# and no checksum, so it is only identifiable by proximity to a key id — which
# is exactly how we pair the two halves below.
#
# `=` is excluded from the *lookbehind* but not the lookahead, and that
# asymmetry is load-bearing. The overwhelmingly common shape of a leaked AWS
# secret is `AWS_SECRET_ACCESS_KEY=<40 chars>` — an `=` immediately precedes
# the value. A symmetric `(?<![A-Za-z0-9/+=])` therefore matches nothing in the
# real world, and because a failed pairing degrades to `unknown` rather than
# erroring, AWS liveness verification would simply never fire while every test
# and every scan still reported success. A 40-char secret needs no base64
# padding (40 chars encode 30 bytes exactly), so a leading `=` is an assignment
# operator, never part of the credential.
_AWS_SECRET = re.compile(r"(?<![A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])")

# How far from the key id to look for its secret half. Four lines covers the
# common shapes (adjacent exports, a two-line YAML block, a credentials file
# stanza) without wandering into an unrelated value further down the file.
_PAIR_WINDOW = 4


class ScanError(RuntimeError):
    """The scan could not run. Raised, never swallowed — a secrets scan that
    silently reports zero findings is the worst outcome this product has."""


def available() -> bool:
    return shutil.which("gitleaks") is not None


def scan(repo_dir: str, *, repo: str, key: bytes, config: str = "", log_opts: str = "",
         timeout: int = 900, verify: Callable[..., liveness.Result] | None = None,
         ) -> list[Finding]:
    """Full-history secret scan. Returns findings; raises `ScanError` if the
    scan itself failed.

    `log_opts` is passed through to gitleaks and is how an incremental nightly
    run works (`--since=…`, or `<last_sha>..HEAD`). Empty means the whole
    history, which is what the first run and the weekly deep scan do.

    `verify` is `liveness.verify` in production and a stub in tests. `None`
    means "do not probe", and every finding comes back `not_checked`.
    """
    if not available():
        raise ScanError("gitleaks is not installed; refusing to report a clean history")
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        raise ScanError(f"{repo_dir} is not a git repository — history cannot be scanned")

    # 0700 (mkdtemp's default), outside the repo. See the module docstring.
    workdir = tempfile.mkdtemp(prefix="hygiene-report-")
    report = os.path.join(workdir, "gitleaks.json")
    # `gitleaks git` is the supported full-history command; `detect` still works
    # in 8.x but is deprecated. `--redact=0` because we need the value in order
    # to fingerprint and to probe it — it is dropped before this call returns.
    argv = ["gitleaks", "git", repo_dir, "--exit-code", "1", "--redact=0",
            "--report-format", "json", "--report-path", report, "--no-banner"]
    if config:
        argv += ["--config", config]
    if log_opts:
        argv += ["--log-opts", log_opts]

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if proc.returncode not in _OK:
            raise ScanError(f"gitleaks exited {proc.returncode}: "
                            f"{(proc.stderr or '').strip()[:400]}")
        try:
            with open(report) as fh:
                results = json.load(fh) or []
        except FileNotFoundError:
            # gitleaks omits the report file entirely when there are no findings.
            results = []
        except (OSError, json.JSONDecodeError) as exc:
            raise ScanError(f"gitleaks report unreadable: {exc}") from exc
        return [_to_finding(item, repo=repo, key=key, repo_dir=repo_dir, verify=verify)
                for item in results]
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"gitleaks timed out after {timeout}s on {repo}") from exc
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _blob(repo_dir: str, commit: str, path: str) -> str:
    """The file as it existed at that commit — including commits whose content
    is long gone from the worktree, which is the whole point."""
    try:
        proc = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=repo_dir,
                              capture_output=True, text=True, timeout=30)
    except (subprocess.SubprocessError, OSError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def find_aws_secret_half(repo_dir: str, commit: str, path: str, line: int) -> str:
    """Locate the secret access key that goes with a key id at `path:line`.

    Read out of the historic blob rather than out of gitleaks' findings: the
    40-char secret half has no distinguishing format, so gitleaks reports it
    only when generic entropy rules happen to fire. Depending on that would
    make AWS liveness verification work on some leaks and silently not on
    others — the credential most worth verifying is the one we would miss.
    """
    text = _blob(repo_dir, commit, path)
    if not text:
        return ""
    lines = text.splitlines()
    lo, hi = max(0, line - 1 - _PAIR_WINDOW), min(len(lines), line + _PAIR_WINDOW)
    for candidate in lines[lo:hi]:
        match = _AWS_SECRET.search(candidate)
        # A key id is itself 20 chars, so it cannot match a 40-char pattern;
        # no need to exclude it explicitly.
        if match:
            return match.group(1)
    return ""


def _to_finding(item: dict, *, repo: str, key: bytes, repo_dir: str,
                verify: Callable[..., liveness.Result] | None) -> Finding:
    """Map one gitleaks result. The raw value dies at the end of this function."""
    # `Secret` is the credential; `Match` is the surrounding matched text, which
    # often includes the variable name. Prefer `Secret` so the fingerprint is of
    # the credential itself and stays stable when the assignment is reformatted.
    raw = item.get("Secret") or item.get("Match") or ""
    rule = item.get("RuleID") or "unknown-rule"
    path = (item.get("File") or "").replace("\\", "/")
    commit = item.get("Commit") or ""
    date = item.get("Date") or ""
    line = int(item.get("StartLine") or 0)
    issuer_key, _issuer = remediation.issuer_for(rule)

    state = liveness.Result("unknown", reason="liveness not requested") if verify is None \
        else _verify(verify, issuer_key, raw, repo_dir=repo_dir, commit=commit,
                     path=path, line=line)
    live = state.state == "live"

    return Finding(
        check="history",
        rule_id=rule,
        finding_type=FINDING_TYPE,
        # `high` here; the bus raises it to `critical` when and only when the
        # credential was proven to still authenticate (see bus.severity_for).
        # Everything in history is a leak; a rotated one is not a 3am page.
        severity="high",
        title=f"{item.get('Description') or rule} is recoverable from {repo} history",
        repo=repo,
        path=path,
        line=line,
        commit=commit,
        author_date=date,
        masked=mask(raw),
        fingerprint=fingerprint(raw, key),
        message=(
            f"{rule} committed in {commit[:8]} ({date or 'unknown date'}) at "
            f"{path}:{line}, value {mask(raw)}. "
            "Still recoverable by anyone who can clone or fork this repository, "
            "whether or not the file exists today."
            + (f" VERIFIED LIVE against {issuer_key}: authenticates as "
               f"{state.detail}." if live else "")),
        remediation=remediation.steps_for_leak(rule, path, repo_hint=repo, live=live),
        liveness="not_checked" if verify is None else state.state,
        liveness_detail=state.detail,
        liveness_reason=state.reason,
        labels={
            "rule": safe_label(rule, 40),
            "issuer": issuer_key,
            "commit": safe_label(commit[:12], 12),
            "entropy": f"{float(item.get('Entropy') or 0):.2f}",
            **({"liveness_reason": safe_label(state.reason, 60)} if state.reason else {}),
        },
    )


def _verify(verify: Callable[..., liveness.Result], issuer: str, raw: str, *,
            repo_dir: str, commit: str, path: str, line: int) -> liveness.Result:
    """Probe one credential, pairing AWS's two halves when this is a key id."""
    if issuer == "aws" and liveness.looks_like_aws_key_id(raw):
        secret_half = find_aws_secret_half(repo_dir, commit, path, line)
        if not secret_half:
            return liveness.Result(
                "unknown",
                reason="AWS key id found but its secret half is not in the same commit; "
                       "cannot verify without both")
        return verify(issuer, secret=secret_half, key_id=raw)
    if issuer == "aws":
        # The 40-char secret half on its own. Unverifiable alone, and reporting
        # it as `unknown` is honest — its key id is a separate finding that
        # does get probed.
        return liveness.Result("unknown",
                               reason="AWS secret half without its key id; not verifiable alone")
    return verify(issuer, secret=raw)
