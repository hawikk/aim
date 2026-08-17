"""Scanner adapter contract and the subprocess runner they share.

The one rule this module exists to enforce: **a scanner that did not run is not
a scanner that found nothing.** Every adapter returns a `ScanOutcome`, and an
outcome carries `error` alongside `findings`. The orchestrator refuses to post
a green check when any outcome has an error — a crashed Semgrep must degrade
the check to `neutral` with the reason on it, never disappear into a log line
while the PR goes green. That is the failure mode this product exists to catch
in other people's systems, so it must not be ours.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field

from ..models import Finding

DEFAULT_TIMEOUT = int(os.environ.get("GATEHOUSE_SCANNER_TIMEOUT", "150"))


@dataclass
class ScanOutcome:
    scanner: str
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    duration_ms: int = 0
    # False when the scanner had nothing in scope to look at (no changed files
    # of its kind). Distinct from "ran and found nothing", which is `ok`.
    skipped: bool = False

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass(frozen=True)
class ToolRun:
    """Result of a scanner CLI invocation.

    `error` is set when the process did not complete successfully for our
    purposes (missing binary, timeout, unexpected exit code). Adapters that
    treat some non-zero exits as success (findings present) still get
    `stderr`/`returncode` so they can disambiguate fatal errors that share
    those exit codes — gitleaks exits 1 for both leaks and FTL.
    """

    stdout: str = ""
    error: str = ""
    stderr: str = ""
    returncode: int = 0


def log(payload: dict) -> None:
    print(json.dumps(payload), file=sys.stderr, flush=True)


def run_tool(argv: list[str], *, cwd: str, timeout: int = DEFAULT_TIMEOUT,
             ok_returncodes: tuple[int, ...] = (0,)) -> ToolRun:
    """Run a scanner CLI and return a ToolRun.

    Scanners overwhelmingly signal "findings present" with a non-zero exit, so
    each adapter declares which codes mean success. Anything else — including a
    timeout or a missing binary — comes back as an error string rather than an
    exception, so one broken scanner degrades the run instead of ending it.
    """
    env = dict(os.environ)
    # No scanner needs the network for the passes we run, and none of them
    # should be phoning home with a customer's source tree. Semgrep and trivy
    # both honour these; the pinned rule/DB bundles are baked into the image.
    env.setdefault("SEMGREP_SEND_METRICS", "off")
    env.setdefault("DO_NOT_TRACK", "1")
    try:
        proc = subprocess.run(
            argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    except FileNotFoundError:
        return ToolRun(error=f"{argv[0]} not installed in this image")
    except subprocess.TimeoutExpired:
        return ToolRun(error=f"{argv[0]} timed out after {timeout}s")
    stderr = proc.stderr or ""
    stdout = proc.stdout or ""
    if proc.returncode not in ok_returncodes:
        detail = (stderr or stdout).strip()[:300]
        return ToolRun(
            stdout=stdout,
            error=f"{argv[0]} exited {proc.returncode}: {detail}",
            stderr=stderr,
            returncode=proc.returncode,
        )
    return ToolRun(stdout=stdout, stderr=stderr, returncode=proc.returncode)


def timed(scanner: str):
    """Decorator: wrap an adapter so it always returns a timed ScanOutcome.

    Also the last-resort guard — an adapter that raises (a scanner changed its
    JSON shape, say) produces an errored outcome, which the orchestrator turns
    into a visibly degraded check rather than a silent pass.
    """

    def wrap(fn):
        def inner(*args, **kwargs) -> ScanOutcome:
            start = time.monotonic()
            try:
                outcome = fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 — deliberately broad, see docstring
                outcome = ScanOutcome(scanner, error=f"{type(exc).__name__}: {exc}"[:300])
            outcome.duration_ms = int((time.monotonic() - start) * 1000)
            log({
                "event": "gatehouse.scanner.done",
                "scanner": scanner,
                "findings": len(outcome.findings),
                "error": outcome.error or None,
                "skipped": outcome.skipped,
                "duration_ms": outcome.duration_ms,
            })
            return outcome

        return inner

    return wrap


def read_line(repo_dir: str, path: str, line: int) -> str:
    """Read one source line for digesting. Never stored, never reported.

    Used only to build `snippet_digest` (a one-way hash) so two distinct hits
    of the same rule in the same file stay distinct across a re-push. Failure
    is not an error: a missing line just means a weaker identity key.
    """
    if not line:
        return ""
    full = os.path.join(repo_dir, path)
    try:
        with open(full, "r", errors="replace") as fh:
            for index, text in enumerate(fh, start=1):
                if index == line:
                    return text
    except OSError:
        return ""
    return ""
