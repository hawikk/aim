"""Runs the three checks over one repo and turns the result into findings,
alerts and a report.

The invariant this module enforces, and the reason it is not just a `for` loop:
**a check that failed is not a check that passed.** Each of the three runs
inside its own try, and a failure is recorded as an `error` on the run rather
than as an absence of findings. `Run.ok` is false when any check errored, the
CLI exits non-zero on it, and the report prints the failures at the top. A
secrets scan that crashes and reports "0 findings, all clear" is the single
worst outcome this product can produce — worse than not running at all, because
it manufactures confidence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import bus
from .checks import history, liveness, tokens, worktree
from .models import Finding, SEVERITY_ORDER, dedupe_key


@dataclass
class Run:
    """One scan of one repo."""

    repo: str
    findings: list[Finding] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    # Which checks actually executed. Distinct from "found nothing" — the
    # report renders these differently and the operator can tell them apart.
    ran: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def by_severity(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (SEVERITY_ORDER.index(
            bus.severity_for(f)), f.check, f.path, f.line))

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            key = bus.severity_for(finding)
            out[key] = out.get(key, 0) + 1
        return out


def scan_repo(repo_dir: str, *, repo: str, key: bytes, config=None,
              verify=liveness.verify, github_token: str = "",
              minimum_scopes: list[str] | None = None, ciem_base: str = "",
              gitleaks_config: str = "", http=None) -> Run:
    """Run all three checks. Never raises for a check-level failure."""
    run = Run(repo=repo)
    http_kwargs = {"http": http} if http is not None else {}

    # ---- check 1: history ------------------------------------------------
    try:
        found = history.scan(repo_dir, repo=repo, key=key, config=gitleaks_config,
                             verify=verify)
        run.findings.extend(found)
        run.ran.append("history")
    except history.ScanError as exc:
        run.errors["history"] = str(exc)

    # ---- check 2: worktree hygiene ---------------------------------------
    try:
        run.findings.extend(worktree.scan(repo_dir, repo=repo, key=key))
        run.ran.append("worktree")
    except worktree.ScanError as exc:
        run.errors["worktree"] = str(exc)

    # ---- check 3: token scope audit --------------------------------------
    # Only runs when a token is configured. "No token to audit" is reported as
    # a skip, never as a pass — see the report renderer.
    if github_token:
        try:
            audit = tokens.audit_github(github_token, **(http_kwargs or {}))
            run.findings.extend(tokens.findings_for_token(
                audit, repo=repo, minimum=minimum_scopes or []))
            run.ran.append("tokens")
        except Exception as exc:  # noqa: BLE001 — surfaced, never swallowed
            run.errors["tokens"] = f"{type(exc).__name__}: {exc}"

    # ---- CIEM deep-link for any live cloud credential (D2) ---------------
    # Driven off the liveness result rather than off the rule id: an ARN only
    # exists because STS answered, which means the credential is live and the
    # blast-radius question is now urgent rather than theoretical.
    for finding in list(run.findings):
        if finding.liveness == "live" and finding.labels.get("issuer") == "aws" \
                and finding.liveness_detail.startswith("arn:"):
            run.findings.append(tokens.principal_finding(
                finding.liveness_detail, repo=repo, fingerprint_=finding.fingerprint,
                ciem_base=ciem_base,
                source=f"An AWS credential leaked in {finding.location}"))
    return run


def publish(run: Run, publisher: bus.Publisher, store=None, *, now: str = "") -> list[str]:
    """Record findings, then publish them. Returns delivered alert ids.

    Store first so `first_seen_at` and `observed_count` on the wire reflect
    this observation, and so a bus outage still leaves durable local state —
    the report on disk is the fallback path when the inbox is unreachable.
    """
    stamp = now or bus.utc_second()
    alerts = []
    # First, and unconditionally when any check failed: the bus is the only
    # channel where "this scan was blind" can reach a human. Zero findings from
    # a broken scanner otherwise looks exactly like zero findings from a clean
    # repo — see bus.degraded_alert.
    if run.errors:
        alerts.append(bus.degraded_alert(run.repo, run.errors, run.ran, now=stamp))
    for finding in run.by_severity():
        seen = store.record(finding) if store is not None else None
        alerts.append(bus.to_alert(
            finding, now=stamp,
            status="new" if (seen is None or seen.is_new) else "updated",
            history=({"first_seen_at": bus.utc_second(_iso(seen.first_seen_at)),
                      "observed_count": seen.observed_count} if seen else None)))
    return publisher.emit(alerts)


def _iso(epoch: int) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def present_keys(run: Run) -> set[str]:
    return {dedupe_key(f) for f in run.findings}


def repo_label(repo_dir: str) -> str:
    """Best-effort `owner/name` for a checkout, falling back to the directory.

    Used for the report title and for `resource.ref`. Parsed from the origin
    remote because that is what the remediation instructions need in order to
    print a real `git clone --mirror` line.
    """
    import subprocess
    try:
        proc = subprocess.run(["git", "remote", "get-url", "origin"], cwd=repo_dir,
                              capture_output=True, text=True, timeout=15)
        url = proc.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        url = ""
    if url:
        cleaned = url.removesuffix(".git")
        for marker in ("github.com/", "github.com:", "gitlab.com/", "gitlab.com:"):
            if marker in cleaned:
                return cleaned.split(marker, 1)[1]
    return os.path.basename(os.path.abspath(repo_dir))
