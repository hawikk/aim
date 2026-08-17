"""trivy — vulnerable dependencies and base images, when the PR changes one.

Scoped by *manifest*, not by line. A CVE in a lockfile has no meaningful line
number, so these findings are file-level (`line=0`), which `DiffScope.touches`
understands: if the PR changed the manifest, its dependency findings are in
scope; if it did not, they belong to the repo's backlog and not to this PR.

Only the vuln scanner is enabled. trivy also does secrets and misconfig, both
of which gitleaks and checkov already own — running all three would post the
same S3 bucket twice under two rule ids and teach engineers to skim the check.

`--skip-db-update --offline-scan` because the vulnerability DB is baked into
the image at build time (see Dockerfile). A scan that silently degrades to "no
DB, no findings" is the exact silent-pass failure this service must not have,
so a missing DB surfaces as a scanner error.

AIM-327: every finding carries CVE, dependency path, fixed version, and an
import-level reachability verdict (`reachable` / `unreachable` / `unknown`)
with evidence. Unreachable findings are still reported and published to the
bus; `checkrun.blocks` refuses to let them fail the merge gate.
"""

from __future__ import annotations

import json
import os

from .. import reachability, severity as sev
from ..models import Finding, digest
from .base import ScanOutcome, run_tool, timed

FINDING_TYPE = "pr_security.vulnerable_dependency"

# Files whose change means "the dependency surface moved". Extending this list
# is how a new ecosystem gets covered. Reachability (import-level) is implemented
# for npm + pip first; other ecosystems still scan, with verdict `unknown`.
MANIFESTS = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "package.json",
    "requirements.txt", "poetry.lock", "pipfile.lock", "go.sum", "go.mod",
    "gemfile.lock", "cargo.lock", "composer.lock", "pom.xml", "build.gradle",
}


def manifests_in(paths: list[str]) -> list[str]:
    hits = []
    for path in paths:
        name = os.path.basename(path).lower()
        if name in MANIFESTS or name.startswith("dockerfile") or name.startswith("requirements"):
            hits.append(path)
    return hits


@timed("trivy")
def scan(repo_dir: str, paths: list[str], *, config: str | None = None) -> ScanOutcome:
    outcome = ScanOutcome("trivy")
    targets = manifests_in(paths)
    if not targets:
        outcome.skipped = True
        return outcome

    argv = ["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln",
            "--skip-db-update", "--offline-scan", "--severity",
            "CRITICAL,HIGH,MEDIUM", "."]
    run = run_tool(argv, cwd=repo_dir)
    if run.error:
        outcome.error = run.error
        return outcome
    try:
        report = json.loads(run.stdout or "{}")
    except json.JSONDecodeError as exc:
        outcome.error = f"trivy output unparseable: {exc}"
        return outcome

    wanted = set(targets)
    seen: set[tuple] = set()
    for result in report.get("Results") or []:
        target = str(result.get("Target") or "").replace("\\", "/")
        # trivy scans the whole tree; keep only the manifests this PR touched.
        if target not in wanted:
            continue
        for vuln in result.get("Vulnerabilities") or []:
            finding = _to_finding(repo_dir, target, vuln)
            if finding is None:
                continue
            key = (target, finding.rule_id, finding.labels.get("pkg", ""))
            if key in seen:  # same CVE via several import paths
                continue
            seen.add(key)
            outcome.findings.append(finding)
    return outcome


def _to_finding(repo_dir: str, target: str, vuln: dict) -> Finding | None:
    """Normalize one trivy vulnerability + attach reachability (AIM-327)."""
    cve = str(vuln.get("VulnerabilityID") or "").strip() or "CVE-UNKNOWN"
    package = str(vuln.get("PkgName") or "").strip()
    installed = str(vuln.get("InstalledVersion") or "").strip()
    fixed = str(vuln.get("FixedVersion") or "").strip()

    # Prefer trivy's own PkgPath when present (monorepo / nested lockfiles).
    pkg_path = str(vuln.get("PkgPath") or "").strip().replace("\\", "/")

    reach = reachability.analyze(
        repo_dir, package, target, installed_version=installed,
    )
    # If trivy gave a concrete package path, prefer it as the leaf of dep_path.
    dep_path = reach.dep_path
    if pkg_path and package:
        # Keep the lockfile root, replace leaf with PkgPath when more specific.
        if pkg_path not in dep_path:
            dep_path = f"{os.path.basename(target) or 'lockfile'} → {pkg_path} → {package}"
            if installed:
                dep_path = f"{dep_path}@{installed}"

    title = f"{cve} in {package} {installed}".strip()[:200]
    message_bits = [
        str(vuln.get("Title") or vuln.get("Description") or cve)[:400],
        f"Reachability: {reach.verdict} — {reach.evidence}",
        f"Dependency path: {dep_path}",
    ]
    if fixed:
        remediation = f"Upgrade {package} to {fixed} or later."
    else:
        remediation = (
            f"No fixed version published for {cve} yet; "
            f"assess reachability ({reach.verdict}) or pin an alternative."
        )

    labels = {
        "cve": cve[:64],
        "pkg": package[:64],
        "fixed_version": (fixed or "none")[:32],
        "installed_version": installed[:32],
        "reachability": reach.verdict,
        "dep_path": dep_path[:128],
        # Evidence is also in message; keep a short form for the bus when
        # label budget allows (bus._cap_labels prioritizes reachability).
        "reach_evidence": reach.evidence[:128],
    }

    return Finding(
        scanner="trivy",
        rule_id=cve,
        finding_type=FINDING_TYPE,
        title=title,
        severity=sev.from_trivy(vuln.get("Severity")),
        path=target,
        line=0,
        message=" | ".join(message_bits)[:600],
        remediation=remediation,
        # Identity is CVE+package only — reachability is a *state* of the same
        # finding and must not rotate alert_id when an import is added/removed.
        snippet_digest=digest(f"{cve}|{package}"),
        labels=labels,
    )
