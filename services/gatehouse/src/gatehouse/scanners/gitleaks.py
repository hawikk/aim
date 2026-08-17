"""gitleaks — secrets. The one scanner whose findings are always critical.

Run with `dir` over the checked-out worktree rather than over history:
gatehouse reports on what this PR *adds*, and `diffscope` already decides that.
Handing gitleaks the git history instead would re-report every secret ever
committed to the repo on every PR, which is a repo-hygiene job (pillar 4), not
a PR gate.

The matched secret is never carried out of this function. `Match` is used to
build a one-way digest and to render a masked hint; `Secret` is dropped on the
floor. The scanner sees the credential because it must; nothing downstream does.

Exit-code note: gitleaks exits 1 when it finds leaks *and* on many
fatal errors (FTL), e.g. an unwritable `--report-path`. Treating 1 as success
and then failing open on a missing report used to mask the real error as
"report unreadable". The report is therefore written to a guaranteed-writable
temp path outside the scanned worktree, and exit 1 without a readable report
is treated as a scanner failure with stderr surfaced. This was also a plausible
cause of the pre-rebuild "scan incomplete" before-shot on (stale image
vs. unwritable report path); the audit reran on a rebuilt image so the original
evidence is gone.
"""

from __future__ import annotations

import json
import os
import tempfile

from ..models import Finding, digest
from .base import ScanOutcome, run_tool, timed

FINDING_TYPE = "pr_security.secret_in_diff"

# gitleaks exits 1 when it finds leaks. That is success for us *only when a
# report was produced*. Fatal errors (FTL) often share exit 1 — see module
# docstring and the missing-report branch below.
_OK = (0, 1)


def mask(match: str) -> str:
    """Keep enough of a match to be recognizable, not enough to be usable.

    Four leading characters identifies the credential *class* (AKIA…, ghp_…,
    xoxb-…) so the engineer knows which system to rotate, and four trailing
    characters lets them tell two keys apart in a vault. The middle is gone.
    """
    text = (match or "").strip()
    if len(text) <= 12:
        return "*" * len(text)
    return f"{text[:4]}{'*' * 8}{text[-4:]}"


@timed("gitleaks")
def scan(repo_dir: str, paths: list[str], *, config: str | None = None) -> ScanOutcome:
    outcome = ScanOutcome("gitleaks")
    if not paths:
        outcome.skipped = True
        return outcome

    # Never write the report inside the scanned worktree: a read-only checkout
    # (or any unwritable cwd) made gitleaks FTL with exit 1, which `_OK`
    # treated as success, which then degraded to "report unreadable".
    # Reserve a unique path under the system temp dir, then remove the empty
    # placeholder so a missing file after the run unambiguously means gitleaks
    # never produced a report (as opposed to an empty leftover from mkstemp).
    report_fd, report = tempfile.mkstemp(prefix="gatehouse-gitleaks-", suffix=".json")
    os.close(report_fd)
    os.remove(report)
    try:
        # gitleaks v8 CLI: `detect` was renamed `git` (history scan) and
        # `dir` (working tree, no VCS). We scan the working tree like the old
        # `detect --no-git` did, so `dir` is the direct replacement.
        argv = ["gitleaks", "dir", ".", "--exit-code", "1",
                "--redact=0", "--report-format", "json", "--report-path", report]
        if config:
            argv += ["--config", config]
        run = run_tool(argv, cwd=repo_dir, ok_returncodes=_OK)
        if run.error:
            outcome.error = run.error
            return outcome
        try:
            with open(report) as fh:
                results = json.load(fh) or []
        except (OSError, json.JSONDecodeError) as exc:
            # Exit was in `_OK` (typically 1) but no usable report → fatal, not
            # findings. Surface stderr so operators see e.g. "Report path is
            # not writable" instead of a generic unreadable-report mask.
            detail = (run.stderr or run.stdout or str(exc)).strip()[:300]
            if detail:
                outcome.error = f"gitleaks failed without a report: {detail}"
            else:
                outcome.error = (
                    f"gitleaks failed without a report "
                    f"(exit {run.returncode}, no stderr): {exc}"
                )
            return outcome

        wanted = set(paths)
        for item in results:
            path = (item.get("File") or "").replace("\\", "/")
            if path not in wanted:
                continue
            rule = item.get("RuleID") or "unknown-rule"
            line = int(item.get("StartLine") or 0)
            outcome.findings.append(Finding(
                scanner="gitleaks",
                rule_id=rule,
                finding_type=FINDING_TYPE,
                title=f"{item.get('Description') or rule} committed in this pull request",
                severity="critical",
                path=path,
                line=line,
                end_line=int(item.get("EndLine") or line),
                message=(f"{rule} matched at {path}:{line} — {mask(item.get('Match', ''))}. "
                         "Treat this credential as compromised."),
                remediation=("Rotate the credential at its issuer first, then remove it from the "
                             "branch. Rotation is the fix; deleting the line is not."),
                # gitleaks' own fingerprint already encodes file+rule+offset; the
                # secret digest is what distinguishes two different keys in one file.
                snippet_digest=digest(item.get("Match") or item.get("Secret") or f"{path}:{line}"),
                labels={"rule": rule[:40], "entropy": f"{item.get('Entropy', 0):.2f}"},
            ))
        return outcome
    finally:
        # The report holds unredacted secrets. Remove it the moment we are done
        # rather than waiting for process exit / workspace teardown.
        try:
            os.remove(report)
        except OSError:
            pass
