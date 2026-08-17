"""The scan pipeline. One function, one PR, one honest answer.

Order matters and each step exists for a reason:

    diff scope -> delta cache -> scanners -> line-scope filter -> merge
      -> suppress -> lifecycle -> alerts -> check run

Two subtleties worth stating up front, because both are easy to get backwards:

* **The cache stores unfiltered per-file findings.** Scope filtering is applied
  *after* the cache, never before it. Caching post-filter results would mean a
  finding on line 90 that was out of scope on push 1 stays invisible on push 2
  when the PR finally touches line 90 — a finding that exists, was seen, and is
  never reported.
* **Resolution is computed, not assumed.** Findings the store saw on a previous
  push and that are absent now are published as `resolved`. Without that, an
  engineer fixes a critical, the inbox keeps showing it, and the inbox stops
  being believed.
"""

from __future__ import annotations

import datetime
import os
import time
from dataclasses import dataclass, field

from . import bus, checkrun, cnapp_parity, dedupe, diffscope, suggest, suppress
from .aireview import provider as aireview_provider
from .aireview import review as aireview
from .cache import Store
from .models import Finding, ScanTarget
from .scanners import REGISTRY, run_all
from .scanners.base import ScanOutcome, log
from .suggest import SuggestedFix
from .workspace import git

VERSION = "0.1.0"


@dataclass
class ScanResult:
    target: ScanTarget
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[tuple[Finding, str]] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    config_problems: list[str] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    scanned_files: int = 0
    cached_files: int = 0
    duration_ms: int = 0
    # AIM-162: populated when the AI reviewer ran (or tried to). Empty dict
    # means the step was off or unconfigured — indistinguishable from a scan
    # that never had the feature, which is the point.
    ai_stats: dict = field(default_factory=dict)
    ai_blocking: bool = False
    # AIM-298: per-repo blocking threshold from `.gatehouse.yml` enforcement.block_on
    # (falls back to GATEHOUSE_FAIL_ON when unset).
    fail_on: str = ""
    # AIM-234: one-click suggested fixes built while the workspace still
    # exists. Empty when the feature is off, the catalogue has no match, or
    # the self-scan gate refused every candidate.
    suggestions: list[SuggestedFix] = field(default_factory=list)
    suggest_enabled: bool = True

    @property
    def conclusion(self) -> str:
        kwargs = {"errors": self.errors, "fail_ai": self.ai_blocking}
        if self.fail_on:
            kwargs["fail_on"] = self.fail_on
        return checkrun.conclusion(self.findings, **kwargs)


def blob_shas(repo_dir: str, paths: list[str]) -> dict[str, str]:
    """path -> git blob SHA at HEAD. The delta cache's key.

    One `ls-tree` call rather than one `rev-parse` per file: a 400-file PR
    would otherwise spend more time forking git than scanning.
    """
    if not paths:
        return {}
    proc = git(["ls-tree", "-r", "-z", "HEAD", "--", *paths], cwd=repo_dir, check=False)
    shas: dict[str, str] = {}
    for entry in proc.stdout.split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if len(parts) >= 3:
            shas[path] = parts[2]
    return shas


def _scan_with_cache(repo_dir: str, paths: list[str], *, repo: str, store: Store | None,
                     enabled: list[str]) -> tuple[list[Finding], list[str], int, int]:
    """Run the enabled scanners, reusing results for unchanged file content.

    Returns (findings, errors, scanned_file_count, reused_file_count).
    """
    if store is None:
        outcomes = run_all(repo_dir, paths, enabled=enabled)
        return (_collect(outcomes), _errors(outcomes), len(paths), 0)

    shas = blob_shas(repo_dir, paths)
    findings: list[Finding] = []
    errors: list[str] = []
    reused_paths: set[str] = set()
    scanned_paths: set[str] = set()

    for name in [n for n in REGISTRY if n in enabled]:
        fresh: list[str] = []
        for path in paths:
            sha = shas.get(path)
            cached = store.cached_findings(repo, name, sha) if sha else None
            if cached is None:
                fresh.append(path)
            else:
                findings.extend(cached)
                reused_paths.add(path)
        if not fresh:
            continue
        scanned_paths.update(fresh)
        outcome = run_all(repo_dir, fresh, enabled=[name])[0]
        errors.extend(_errors([outcome]))
        findings.extend(outcome.findings)
        if outcome.ok:
            # Only a clean run may seed the cache. Caching the empty result of
            # a crashed scanner would make the *next* push reuse "no findings"
            # for a file nobody ever successfully scanned.
            by_path: dict[str, list[Finding]] = {p: [] for p in fresh}
            for finding in outcome.findings:
                by_path.setdefault(finding.path, []).append(finding)
            for path, items in by_path.items():
                sha = shas.get(path)
                if sha:
                    store.put_findings(repo, name, sha, items)

    return findings, errors, len(scanned_paths), len(reused_paths - scanned_paths)


def _collect(outcomes: list[ScanOutcome]) -> list[Finding]:
    return [f for outcome in outcomes for f in outcome.findings]


def _errors(outcomes: list[ScanOutcome]) -> list[str]:
    return [f"{o.scanner}: {o.error}" for o in outcomes if o.error]


def scan(repo_dir: str, target: ScanTarget, *, store: Store | None = None,
         config_text: str = "", base_ref: str = "", enabled: list[str] | None = None,
         publisher: bus.Publisher | None = None, check_run_id: int | str = 0,
         all_files: bool = False, ai: bool = True,
         ai_provider: "aireview_provider.Provider | None" = None,
         build_suggestions: bool = True,
         suggest_self_scan=None) -> ScanResult:
    """Scan one PR's changed lines and return everything needed to report."""
    started = time.monotonic()
    result = ScanResult(target=target)
    config = suppress.parse(config_text) if config_text else suppress.Config()
    result.config_problems = list(config.problems)
    result.ai_blocking = config.ai_blocking
    result.suggest_enabled = config.suggest_enabled
    # AIM-298: repo may tighten/loosen the service default via enforcement.block_on.
    result.fail_on = config.block_on or checkrun.FAIL_ON

    active = [n for n in (enabled or list(REGISTRY)) if n not in config.disabled_scanners]

    if all_files:
        # Baseline mode (CLI only): no diff, scan the whole tree. Used to seed a
        # repo's backlog, never by the PR path — a PR gate that reports the
        # whole repo's history is a PR gate nobody will keep.
        scope = diffscope.DiffScope()
        paths = _tracked_files(repo_dir)
        for path in paths:
            scope.added_lines[path] = [(1, 10**7)]
    else:
        base = base_ref or diffscope.merge_base(repo_dir)
        scope = diffscope.compute(repo_dir, base=base)
        paths = scope.paths

    raw, errors, scanned, reused = _scan_with_cache(
        repo_dir, paths, repo=target.repo_full_name, store=store, enabled=active)
    result.errors = errors
    result.scanned_files = scanned
    result.cached_files = reused

    in_scope = [f for f in raw if scope.touches(f.path, f.line, f.end_line)]
    merged = dedupe.merge(in_scope, target.identity_ref)
    # AIM-329: name the CNAPP posture rule each IaC finding would become
    # post-deploy (code-to-cloud story on the PR, before AIM-305 asset link).
    merged = cnapp_parity.enrich_findings(
        merged, align_severity=cnapp_parity.env_align_severity())
    result.findings, result.suppressed = suppress.apply(merged, config)
    result.config_problems = list(config.problems)  # apply() appends expiry notes

    # AIM-162: the AI reviewer runs after suppression and before alerts, so its
    # findings flow through the alert lifecycle like any finding. Off/unconfigured
    # provider or a repo opt-out means the step simply does not happen.
    if ai and config.ai_enabled is not False:
        ai_prov = ai_provider or aireview_provider.from_env()
        if ai_prov is not None:
            knobs = aireview_provider.settings()
            ai_findings, relabeled, stats = aireview.run(
                repo_dir, scope, provider=ai_prov, model=knobs["model"],
                scanner_findings=result.findings,
                max_bytes=knobs["max_bytes"], context_lines=knobs["context_lines"],
                max_graph_bytes=knobs.get("max_graph_bytes"),
                include_graph=knobs.get("include_graph", True),
                price_in=knobs["price_in"], price_out=knobs["price_out"])
            result.findings = relabeled + ai_findings
            result.ai_stats = stats
            if stats.get("error"):
                # Soft failure: the error string lands in the summary's
                # incomplete-scan warning and degrades the check to neutral —
                # the exact semantics `checkrun.conclusion` gives scanner errors.
                result.errors.append(f"ai-review: {stats['error']}")

    # AIM-234: build one-click fixes while the workspace still holds the PR
    # tree. Must run before the caller tears the checkout down. Self-scan uses
    # the same scanners; suggestions never affect conclusion.
    if build_suggestions and config.suggest_enabled:
        kwargs = {}
        if suggest_self_scan is not None:
            kwargs["self_scan"] = suggest_self_scan
        # Only scanner findings — AI-review findings are filtered inside propose.
        scanner_findings = [f for f in result.findings if f.scanner != "ai-review"]
        result.suggestions = suggest.propose(
            scanner_findings, repo_dir=repo_dir,
            repo_full_name=target.repo_full_name, enabled=True, **kwargs)

    result.alerts = _build_alerts(result, store=store, check_run_id=check_run_id)
    if publisher:
        publisher.emit(result.alerts)
        if publisher.rejected:
            # A finding that never reached the bus is a finding the SOC will not
            # see. That degrades the check; it does not disappear into a log.
            result.errors.append(
                f"alert bus: {publisher.rejected} finding(s) could not be published")

    result.duration_ms = int((time.monotonic() - started) * 1000)
    log({"event": "gatehouse.scan.done", "repo": target.repo_full_name,
         "pr": target.pr_number, "findings": len(result.findings),
         "suppressed": len(result.suppressed), "resolved": len(result.resolved),
         "suggestions": sum(1 for s in result.suggestions if s.is_suggestion),
         "errors": result.errors, "scanned_files": scanned, "reused_files": reused,
         "duration_ms": result.duration_ms})
    return result


def _build_alerts(result: ScanResult, *, store: Store | None,
                  check_run_id: int | str) -> list[dict]:
    """Map findings onto the bus contract, including the ones that went away."""
    now = bus.utc_second(datetime.datetime.now(datetime.timezone.utc))
    target = result.target
    alerts: list[dict] = []
    live_keys: set[str] = set()

    for finding, status, reason in (
        [(f, "new", "") for f in result.findings]
        + [(f, "suppressed", r) for f, r in result.suppressed]
    ):
        # Identity is repo-scoped (AIM-299 AC#3): same secret on five PRs → one
        # dedupe_key. resource.ref still names *this* PR for action.
        key = dedupe.dedupe_key(finding, target.identity_ref)
        live_keys.add(key)
        history = {}
        if store:
            history = store.record(target.repo_full_name, target.pr_number, key,
                                   now=now, alert_id=bus.alert_id_for(key))
            if status == "new" and not history.get("is_new"):
                # Seen before — either an earlier push of this PR, or the same
                # finding already open on another PR of this repo. `updated`
                # means "still here / also here", never a second open issue.
                status = "updated"
        alerts.append(bus.to_alert(
            finding, target, now=now, status=status, history=history,
            producer_version=VERSION, check_run_id=check_run_id,
            suppression_reason=reason))

    if store:
        gone_here = [k for k in store.seen(target.repo_full_name, target.pr_number)
                     if k not in live_keys]
        # Only keys with zero remaining PR occurrences become `resolved`.
        # A fix on PR #1 while PR #2 still carries the secret must not close
        # the inbox row (no silent close / no zombie after a partial fix).
        fully_gone = store.forget(target.repo_full_name, target.pr_number, gone_here)
        for key in fully_gone:
            alerts.append(_resolved_alert(key, target, now=now, check_run_id=check_run_id))
        result.resolved = fully_gone
    return alerts


def _resolved_alert(key: str, target: ScanTarget, *, now: str,
                    check_run_id: int | str) -> dict:
    """A minimal, contract-valid `resolved` alert.

    Carries the same `alert_id`/`dedupe_key` as the alert that opened the
    finding, which is the whole mechanism: a consumer keyed on `alert_id` (§7.2)
    closes the row it already has. Severity is `informational` because the
    *event* being reported is "this went away" — restating the original
    severity would re-rank a fixed problem to the top of the queue.
    """
    return {
        "schema_version": bus.SCHEMA_VERSION,
        "alert_id": bus.alert_id_for(key),
        "dedupe_key": key,
        "pillar": bus.PILLAR,
        "producer": {"name": bus.PRODUCER_NAME, "version": VERSION},
        "finding_type": "pr_security.finding_resolved",
        "title": "Pull-request finding no longer present after a new push",
        "severity": "informational",
        "severity_id": 1,
        "status": "resolved",
        "observed_at": now,
        "first_seen_at": now,
        "last_seen_at": now,
        "resource": {
            "kind": "pull_request", "ref": target.resource_ref,
            "display": f"{target.repo_full_name}#{target.pr_number}"[:120],
            "provider": "github", "account_ref": target.owner[:128], "region": None,
        },
        "subject_ref": None,
        "evidence": {
            "source_uri": bus.source_uri(target, key, check_run_id),
            "detail_count": 1,
            "summary": "The finding was not reproduced by the scan of the current head.",
        },
        "labels": {"head_sha": (target.head_sha or "")[:12]},
    }


def _tracked_files(repo_dir: str) -> list[str]:
    proc = git(["ls-files", "-z"], cwd=repo_dir, check=False)
    return [p for p in proc.stdout.split("\0") if p]


def today() -> datetime.date:
    return datetime.date.fromtimestamp(int(os.environ.get("GATEHOUSE_FAKE_TODAY", "0"))
                                       or time.time())
