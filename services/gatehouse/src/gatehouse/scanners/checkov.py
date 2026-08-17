"""checkov — IaC misconfiguration on changed Terraform / CloudFormation / K8s.

Two things this adapter has to get right:

* **`--soft-fail`.** checkov exits 1 when any check fails, which is its normal
  and expected state here. Without soft-fail the runner would classify a
  perfectly good scan as a crashed scanner.
* **The output is sometimes a list.** checkov emits one report object per
  framework, and when more than one framework matches it emits a JSON array of
  them. Reading `report["results"]` unconditionally works right up until the PR
  touches both a `.tf` and a `Chart.yaml`, at which point every IaC finding
  silently disappears. `_reports()` normalizes both shapes.

Only frameworks whose files actually changed are enabled, which is what keeps
this inside the 3-minute budget on a repo with a large `terraform/` tree.
"""

from __future__ import annotations

import json
import os

from .. import severity as sev
from ..models import Finding, digest
from .base import ScanOutcome, run_tool, timed

FINDING_TYPE = "pr_security.iac_misconfig"
# CKV_SECRET_* are credential findings that happen to live in IaC. Typing them
# as secrets rather than as misconfigurations is what lets dedupe recognize
# them as the same defect gitleaks reports on the same line.
SECRET_TYPE = "pr_security.hardcoded_secret"
_OK = (0,)  # with --soft-fail, anything else is a real failure

# extension -> checkov framework. Deliberately narrow: `--framework all` pulls
# in secrets and SCA passes that gitleaks and trivy already own, and duplicate
# findings from two scanners is the noise that gets a bot muted.
FRAMEWORKS = {
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".json": "cloudformation",
    ".yaml": "kubernetes",
    ".yml": "kubernetes",
    "dockerfile": "dockerfile",
}


def frameworks_for(paths: list[str]) -> list[str]:
    found = []
    for path in paths:
        name = os.path.basename(path).lower()
        key = "dockerfile" if name.startswith("dockerfile") else os.path.splitext(name)[1]
        framework = FRAMEWORKS.get(key)
        if framework and framework not in found:
            found.append(framework)
    return found


def _reports(payload) -> list[dict]:
    """checkov returns an object for one framework and a list for several."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return [payload] if isinstance(payload, dict) else []


def _repo_path(item: dict) -> str:
    """The path relative to the repo root — which is NOT `file_path`.

    When checkov is invoked with `-f infra/exports.tf`, `file_path` comes back
    as `/exports.tf`: relative to the *file's own directory*, not to the scan
    root. Using it means every finding is filed against a path that does not
    exist in the repo, so diff scoping drops all of them and a PR that adds a
    public S3 bucket comes back green. `repo_file_path` is the one relative to
    where checkov was invoked, which is the ephemeral checkout root.
    """
    raw = item.get("repo_file_path") or item.get("file_path") or ""
    return str(raw).lstrip("/").replace("\\", "/")


@timed("checkov")
def scan(repo_dir: str, paths: list[str], *, config: str | None = None) -> ScanOutcome:
    outcome = ScanOutcome("checkov")
    frameworks = frameworks_for(paths)
    if not frameworks:
        outcome.skipped = True
        return outcome

    argv = ["checkov", "--quiet", "--compact", "--soft-fail", "-o", "json",
            "--framework", *frameworks]
    for path in paths:
        if frameworks_for([path]):
            argv += ["-f", path]
    run = run_tool(argv, cwd=repo_dir, ok_returncodes=_OK)
    if run.error:
        outcome.error = run.error
        return outcome
    try:
        payload = json.loads(run.stdout or "{}")
    except json.JSONDecodeError as exc:
        outcome.error = f"checkov output unparseable: {exc}"
        return outcome

    for report in _reports(payload):
        results = report.get("results") or {}
        for item in results.get("failed_checks") or []:
            check_id = str(item.get("check_id") or "checkov")
            path = _repo_path(item)
            span = item.get("file_line_range") or [0, 0]
            line = int(span[0] or 0)
            end_line = int(span[1] or line)
            resource = str(item.get("resource") or "")
            outcome.findings.append(Finding(
                scanner="checkov",
                rule_id=check_id,
                finding_type=SECRET_TYPE if check_id.startswith("CKV_SECRET") else FINDING_TYPE,
                title=str(item.get("check_name") or check_id)[:200],
                severity=sev.from_checkov(check_id, item.get("severity")),
                path=path,
                line=line,
                end_line=end_line,
                message=(f"{check_id} failed on `{resource}` "
                         f"({report.get('check_type', 'iac')}).")[:600],
                remediation=str(item.get("guideline") or "")[:500],
                # The resource address, not the source text: the same
                # misconfiguration keeps one identity when the block moves.
                snippet_digest=digest(f"{check_id}|{resource}"),
                labels={"check": check_id[:64], "framework": str(report.get("check_type") or "")[:32]},
            ))
    return outcome
