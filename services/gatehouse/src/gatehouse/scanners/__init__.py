"""The scanner registry and the fan-out that runs them.

Scanners run concurrently in threads. They are subprocesses, so the GIL is not
the constraint — wall-clock is dominated by four independent CLIs, and running
them in sequence is what would put the 3-minute acceptance budget at risk on a
4-vCPU box (D6). The pool is capped at the scanner count for the same reason:
four CPU-bound processes on four vCPUs is the design point, not eight.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from . import checkov, gitleaks, semgrep, trivy
from .base import ScanOutcome

REGISTRY = {
    "gitleaks": gitleaks.scan,
    "semgrep": semgrep.scan,
    "checkov": checkov.scan,
    "trivy": trivy.scan,
}


def run_all(repo_dir: str, paths: list[str], *, enabled: list[str] | None = None,
            configs: dict[str, str] | None = None) -> list[ScanOutcome]:
    """Run every enabled scanner over `paths`, in parallel. Never raises.

    Order of the returned list follows REGISTRY, not completion, so a check-run
    summary reads the same way on every run.
    """
    names = [n for n in REGISTRY if not enabled or n in enabled]
    configs = configs or {}
    with ThreadPoolExecutor(max_workers=max(1, len(names))) as pool:
        futures = {
            name: pool.submit(REGISTRY[name], repo_dir, paths, config=configs.get(name))
            for name in names
        }
        return [futures[name].result() for name in names]
