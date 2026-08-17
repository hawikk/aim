"""Out-of-band merge auditor (Epic C D-C3 Tier 1).

GitHub Actions `merge-audit.yml` shares a failure domain with the gates: when
billing or the runner dies, the auditor dies with them. That is exactly what
let #52–#55 land on `main` with every check red and no bypass record (§0 of
the cicd-enforcement architecture).

This module is the independent control:

* runs as a gatehouse process (CLI / container), not a GH Actions job
* re-derives what `.github/required-checks.json` required of a merged PR
* classifies each non-green required check as either:
    - **deliberate bypass** — `security-bypass` label + a stated reason, or
    - **unauthorized bypass** — no reason; critical alert + optional auto-revert
* emits a `security.alert/v1` with actor, PR, rule (check name), reason,
  timestamp so the security-event queue sees it — not only a GitHub issue

Honest naming (D-C3): Tier 1 is **detect, attribute, and revert**. It cannot
make GitHub refuse a merge on a free personal plan. Tier 2 (native branch
protection) needs GitHub Pro; see `scripts/apply_branch_protection.py`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote

from . import bus, evidence as evidence_mod
from .models import SEVERITY_ID

BYPASS_LABEL = "security-bypass"
BYPASS_REASON_RE = re.compile(
    r"(?im)^\s*(?:bypass[-_ ]?reason|reason)\s*:\s*(.+?)\s*$",
)
BYPASS_MARKER = "<!-- aim-298-merge-bypass -->"
REASON_MIN_LEN = 12
DEFAULT_GATE_PATH = ".github/required-checks.json"

# finding_type is open vocabulary under security.alert/v1 (pattern a.b).
FINDING_TYPE_UNAUTHORIZED = "pr_security.merge_bypass"
FINDING_TYPE_DELIBERATE = "pr_security.audited_bypass"
FINDING_TYPE_UNVERIFIED = "pr_security.merge_unverified"


def _log(payload: dict) -> None:
    print(json.dumps(payload), file=sys.stderr, flush=True)


@dataclass
class GateConfig:
    """The required-checks rule (`.github/required-checks.json`)."""

    always: list[str] = field(default_factory=list)
    conditional: list[dict] = field(default_factory=list)
    not_required: dict[str, str] = field(default_factory=dict)
    refuse_labels: list[str] = field(default_factory=list)
    refuse_paths: list[str] = field(default_factory=list)
    allowed_base_refs: list[str] = field(default_factory=list)
    bypass_label: str = BYPASS_LABEL
    # Severity of an unauthorized merge-through-red (default critical).
    unauthorized_severity: str = "critical"
    # Severity of a deliberate, reasoned bypass (still in the queue).
    deliberate_severity: str = "high"
    # When true, open a revert PR for unauthorized critical bypasses.
    auto_revert: bool = True


@dataclass
class CheckVerdict:
    name: str
    required: bool
    conclusion: str | None  # success / failure / … / None if missing
    status: str | None      # completed / queued / in_progress / None


@dataclass
class BypassRecord:
    """One auditable bypass event. Serializable; bus-mapped."""

    repo: str
    pr_number: int
    head_sha: str
    actor: str
    merged_at: str
    rule: str                 # check name or "required-checks"
    reason: str               # human reason, or synthetic for unauthorized
    deliberate: bool
    check_conclusions: dict[str, str] = field(default_factory=dict)
    policy_hash: str = ""
    verified: bool = True
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "repo": self.repo,
            "pr_number": self.pr_number,
            "head_sha": self.head_sha,
            "actor": self.actor,
            "merged_at": self.merged_at,
            "rule": self.rule,
            "reason": self.reason,
            "deliberate": self.deliberate,
            "check_conclusions": self.check_conclusions,
            "policy_hash": self.policy_hash,
            "verified": self.verified,
            "timestamp": self.timestamp or self.merged_at,
        }


@dataclass
class AuditResult:
    pr_number: int
    head_sha: str
    clean: bool
    unverified: bool
    bypasses: list[BypassRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    revert_pr: int | None = None
    # — full required-check verdicts for durable evidence retention.
    verdicts: list[CheckVerdict] = field(default_factory=list)
    classification: str = "unknown"
    policy_hash: str = ""
    actor: str = ""
    merged_at: str = ""
    merge_sha: str = ""


def load_gate_config(raw: dict | str | bytes) -> GateConfig:
    data = json.loads(raw) if isinstance(raw, (str, bytes)) else dict(raw)
    severity = data.get("bypass") or {}
    if not isinstance(severity, dict):
        severity = {}
    return GateConfig(
        always=list(data.get("always") or []),
        conditional=list(data.get("conditional") or []),
        not_required=dict(data.get("not_required") or {}),
        refuse_labels=list(data.get("refuse_labels") or []),
        refuse_paths=list(data.get("refuse_paths") or []),
        allowed_base_refs=list(data.get("allowed_base_refs") or ["main"]),
        bypass_label=str(severity.get("label") or data.get("bypass_label") or BYPASS_LABEL),
        unauthorized_severity=str(severity.get("unauthorized_severity") or "critical"),
        deliberate_severity=str(severity.get("deliberate_severity") or "high"),
        auto_revert=bool(severity.get("auto_revert", True)),
    )


def policy_hash(cfg: GateConfig) -> str:
    """Stable short hash of the rule so audits name *which* policy applied."""
    blob = json.dumps({
        "always": cfg.always,
        "conditional": [
            {"check": c.get("check"), "when": c.get("when_paths_changed")}
            for c in cfg.conditional
        ],
        "bypass_label": cfg.bypass_label,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def matches_path(file: str, pattern: str) -> bool:
    """Same semantics as GitHub's `on.pull_request.paths` / auto-merge gate."""
    if pattern.endswith("/"):
        return file.startswith(pattern)
    if any(ch in pattern for ch in "*?"):
        parts = pattern.split("**")
        rx = ".*".join(re.escape(p).replace(r"\*", "[^/]*").replace(r"\?", ".") for p in parts)
        return re.fullmatch(rx, file) is not None
    return file == pattern or file.startswith(pattern.rstrip("/") + "/")


def required_checks_for(cfg: GateConfig, changed_files: list[str]) -> list[str]:
    names = list(cfg.always)
    for entry in cfg.conditional:
        check = entry.get("check")
        when = entry.get("when_paths_changed") or []
        if not check:
            continue
        if any(matches_path(f, p) for f in changed_files for p in when):
            names.append(str(check))
    # Stable unique order
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def extract_bypass_reason(bodies: list[str]) -> str:
    """First matching `Bypass-Reason: …` / `Reason: …` line across PR bodies."""
    for body in bodies:
        if not body:
            continue
        m = BYPASS_REASON_RE.search(body)
        if m:
            reason = " ".join(m.group(1).split())
            if len(reason) >= REASON_MIN_LEN:
                return reason
    return ""


def classify_checks(
    required: list[str],
    check_runs: list[dict],
) -> list[CheckVerdict]:
    """Map required check names onto the latest run per name at a head SHA."""
    by_name: dict[str, dict] = {}
    for run in check_runs:
        name = run.get("name") or ""
        if not name:
            continue
        # Prefer the latest completed; if none, keep whatever is newest.
        prev = by_name.get(name)
        if prev is None:
            by_name[name] = run
            continue
        # Higher id = later run in practice.
        if int(run.get("id") or 0) >= int(prev.get("id") or 0):
            by_name[name] = run

    verdicts: list[CheckVerdict] = []
    for name in required:
        run = by_name.get(name)
        if not run:
            verdicts.append(CheckVerdict(name=name, required=True,
                                         conclusion=None, status=None))
            continue
        verdicts.append(CheckVerdict(
            name=name, required=True,
            conclusion=(run.get("conclusion") or None),
            status=(run.get("status") or None),
        ))
    return verdicts


def is_green(v: CheckVerdict) -> bool:
    return v.conclusion == "success" and (v.status in (None, "completed"))


def non_green(verdicts: list[CheckVerdict]) -> list[CheckVerdict]:
    return [v for v in verdicts if not is_green(v)]


def audit_merged_pr(
    *,
    repo: str,
    pr: dict,
    changed_files: list[str],
    check_runs: list[dict],
    comments: list[dict],
    cfg: GateConfig,
    now: str | None = None,
) -> AuditResult:
    """Pure evaluation of one merged PR. No I/O."""
    now = now or bus.utc_second(None)
    number = int(pr.get("number") or 0)
    head_sha = ((pr.get("head") or {}).get("sha") or pr.get("merge_commit_sha") or "")
    actor = (
        ((pr.get("merged_by") or {}).get("login"))
        or ((pr.get("user") or {}).get("login"))
        or "unknown"
    )
    merged_at = pr.get("merged_at") or now
    labels = {((lab.get("name") if isinstance(lab, dict) else lab) or "").lower()
              for lab in (pr.get("labels") or [])}

    notes: list[str] = []
    required = required_checks_for(cfg, changed_files)
    if not required and not cfg.always:
        return AuditResult(
            pr_number=number, head_sha=head_sha, clean=False, unverified=True,
            notes=["gate config has no always/conditional checks — cannot verify"],
            classification="unverified",
            actor=actor, merged_at=merged_at,
            merge_sha=pr.get("merge_commit_sha") or "",
        )

    verdicts = classify_checks(required, check_runs)
    bad = non_green(verdicts)
    ph = policy_hash(cfg)
    merge_sha = pr.get("merge_commit_sha") or ""
    if not bad:
        return AuditResult(
            pr_number=number, head_sha=head_sha, clean=True, unverified=False,
            notes=[f"all {len(required)} required check(s) green at {head_sha[:12]}"],
            verdicts=verdicts, classification="clean", policy_hash=ph,
            actor=actor, merged_at=merged_at, merge_sha=merge_sha,
        )

    # Deliberate bypass needs both the label and a free-text reason.
    bodies = [pr.get("body") or ""]
    bodies.extend(c.get("body") or "" for c in comments)
    reason = extract_bypass_reason(bodies)
    has_label = cfg.bypass_label.lower() in labels
    deliberate = has_label and bool(reason)

    if has_label and not reason:
        notes.append(
            f"label `{cfg.bypass_label}` present but no `Bypass-Reason: …` "
            f"(≥{REASON_MIN_LEN} chars) — treating as unauthorized"
        )

    bypasses: list[BypassRecord] = []
    for v in bad:
        state = v.conclusion or v.status or "missing"
        if deliberate:
            rec_reason = reason
        else:
            rec_reason = (
                f"merged with required check `{v.name}` = {state}; "
                f"no audited bypass (need label `{cfg.bypass_label}` + Bypass-Reason)"
            )
        bypasses.append(BypassRecord(
            repo=repo,
            pr_number=number,
            head_sha=head_sha,
            actor=actor,
            merged_at=merged_at,
            rule=v.name,
            reason=rec_reason,
            deliberate=deliberate,
            check_conclusions={v.name: state},
            policy_hash=ph,
            verified=True,
            timestamp=now,
        ))

    notes.append(
        f"{'deliberate' if deliberate else 'unauthorized'} bypass: "
        f"{len(bypasses)} required check(s) not green"
    )
    classification = "deliberate_bypass" if deliberate else "unauthorized_bypass"
    return AuditResult(
        pr_number=number, head_sha=head_sha, clean=False, unverified=False,
        bypasses=bypasses, notes=notes, verdicts=verdicts,
        classification=classification, policy_hash=ph,
        actor=actor, merged_at=merged_at, merge_sha=merge_sha,
    )


def bypass_to_alert(record: BypassRecord, *, now: str | None = None) -> dict:
    """Map one BypassRecord onto security.alert/v1 for the security-event queue."""
    now = now or record.timestamp or bus.utc_second(None)
    deliberate = record.deliberate
    severity = "high" if deliberate else "critical"
    # Honour explicit severity if already stamped via labels path.
    finding_type = FINDING_TYPE_DELIBERATE if deliberate else FINDING_TYPE_UNAUTHORIZED
    title = (
        f"Audited merge bypass on {record.repo}#{record.pr_number}: {record.rule}"
        if deliberate else
        f"Unauthorized merge bypass on {record.repo}#{record.pr_number}: {record.rule}"
    )
    # Stable id: same bypass re-audited must not flood the inbox.
    seed = f"bypass|{record.repo}|{record.pr_number}|{record.rule}|{record.head_sha}"
    dedupe = hashlib.sha256(seed.encode()).hexdigest()
    labels = {
        "scanner": "merge-audit",
        "rule": record.rule[:128],
        "head_sha": (record.head_sha or "")[:12],
        "actor": (record.actor or "unknown")[:128],
        "deliberate": "true" if deliberate else "false",
        "policy_hash": (record.policy_hash or "")[:16],
    }
    if record.reason:
        labels["bypass_reason"] = record.reason[:128]

    # source_uri path segments must match the contract's safe charset
    # ([A-Za-z0-9._~-]) — check names like "secret scan" need sanitizing.
    safe_repo = re.sub(r"[^A-Za-z0-9._~-]", "_", record.repo)
    safe_rule = re.sub(r"[^A-Za-z0-9._~-]", "_", record.rule)[:48] or "check"
    alert = {
        "schema_version": bus.SCHEMA_VERSION,
        "alert_id": bus.alert_id_for(dedupe),
        "dedupe_key": dedupe,
        "pillar": bus.PILLAR,
        "producer": {"name": bus.PRODUCER_NAME, "version": "0.1.0"},
        "finding_type": finding_type,
        "title": title[:bus.MAX_TITLE],
        "severity": severity,
        "severity_id": SEVERITY_ID[severity],
        "status": "new",
        "observed_at": now,
        "first_seen_at": now,
        "last_seen_at": now,
        "resource": {
            "kind": "pull_request",
            "ref": f"github:{record.repo}#{record.pr_number}",
            "display": f"{record.repo}#{record.pr_number}"[:120],
            "provider": "github",
            "account_ref": record.repo.split("/", 1)[0][:128],
            "region": None,
        },
        "subject_ref": None,
        "evidence": {
            "source_uri": (
                f"gatehouse:/repos/{safe_repo}"
                f"/pulls/{record.pr_number}/bypass/{safe_rule}"
            ),
            "detail_count": 1,
            "summary": (
                f"actor={record.actor}; rule={record.rule}; "
                f"sha={(record.head_sha or '')[:12]}; "
                f"reason={record.reason[:80]}"
            )[:bus.MAX_SUMMARY],
        },
        "labels": bus._cap_labels(labels),
        "remediation_hint": (
            "Documented deliberate bypass — security should review the reason "
            "and confirm the residual risk is accepted."
            if deliberate else
            "Unauthorized bypass: open or land the auto-revert, rotate any "
            "exposed secrets, and treat the merge as untrusted until re-scanned."
        ),
    }
    return alert


# ---------------------------------------------------------------------------
# GitHub transport helpers (injectable for tests)
# ---------------------------------------------------------------------------

HttpFn = Callable[[str, str, str, dict | None], Any]


def _gh_request(method: str, url: str, token: str, body: dict | None = None) -> Any:
    import urllib.error
    import urllib.request

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "gatehouse-merge-audit/0.1")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise RuntimeError(f"{method} {url} -> {exc.code}: {detail}") from exc
    if not payload:
        return {}
    return json.loads(payload)


def fetch_gate_config(repo: str, token: str, *, ref: str = "",
                      path: str = DEFAULT_GATE_PATH,
                      request: HttpFn = _gh_request,
                      api_root: str = "https://api.github.com") -> GateConfig:
    ref_q = f"?ref={quote(ref)}" if ref else ""
    url = f"{api_root}/repos/{repo}/contents/{path}{ref_q}"
    # raw content
    import urllib.request
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github.raw+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "gatehouse-merge-audit/0.1")
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
    return load_gate_config(raw)


def list_recent_merged_prs(
    repo: str, token: str, *, since_iso: str = "", limit: int = 20,
    request: HttpFn = _gh_request,
    api_root: str = "https://api.github.com",
) -> list[dict]:
    url = (f"{api_root}/repos/{repo}/pulls?state=closed&sort=updated"
           f"&direction=desc&per_page={min(limit, 50)}")
    items = request("GET", url, token, None)
    out: list[dict] = []
    for pr in items or []:
        if not pr.get("merged_at"):
            continue
        if since_iso and pr["merged_at"] < since_iso:
            continue
        out.append(pr)
    return out


def list_pr_files(repo: str, number: int, token: str, *,
                  request: HttpFn = _gh_request,
                  api_root: str = "https://api.github.com") -> list[str]:
    files: list[str] = []
    for page in range(1, 11):
        url = (f"{api_root}/repos/{repo}/pulls/{number}/files"
               f"?per_page=100&page={page}")
        batch = request("GET", url, token, None) or []
        for f in batch:
            if f.get("filename"):
                files.append(f["filename"])
        if len(batch) < 100:
            break
    return files


def list_check_runs(repo: str, head_sha: str, token: str, *,
                    request: HttpFn = _gh_request,
                    api_root: str = "https://api.github.com") -> list[dict]:
    runs: list[dict] = []
    for page in range(1, 11):
        url = (f"{api_root}/repos/{repo}/commits/{head_sha}/check-runs"
               f"?per_page=100&page={page}")
        payload = request("GET", url, token, None) or {}
        batch = payload.get("check_runs") if isinstance(payload, dict) else payload
        batch = batch or []
        runs.extend(batch)
        if len(batch) < 100:
            break
    return runs


def list_issue_comments(repo: str, number: int, token: str, *,
                        request: HttpFn = _gh_request,
                        api_root: str = "https://api.github.com") -> list[dict]:
    url = f"{api_root}/repos/{repo}/issues/{number}/comments?per_page=100"
    return list(request("GET", url, token, None) or [])


def open_revert_pr(
    repo: str, *, merge_commit_sha: str, pr_number: int, token: str,
    reason: str, request: HttpFn = _gh_request,
    api_root: str = "https://api.github.com",
    base_ref: str = "main",
) -> int | None:
    """Open a revert PR for an unauthorized bypass. Returns PR number or None.

    Requires a token with `contents: write` + `pull_requests: write`. The
    scan App token is least-privilege (`contents: read`) by design, so callers
    should pass `GATEHOUSE_REVERT_TOKEN` (or a PAT) here rather than widen the
    scan App. Returns None when the API refuses or the commit cannot reverse.
    """
    if not merge_commit_sha or not token:
        return None
    # Resolve default branch if needed
    branch = f"aim-298-revert-pr-{pr_number}-{merge_commit_sha[:7]}"
    # Get parent of merge commit to branch from, or use base_ref
    commit = request("GET", f"{api_root}/repos/{repo}/commits/{merge_commit_sha}",
                     token, None) or {}
    parents = commit.get("parents") or []
    if not parents:
        _log({"event": "merge_audit.revert_no_parent", "sha": merge_commit_sha})
        return None
    parent_sha = parents[0]["sha"]

    # Create branch at parent, then reverse the merge via a tree? Simpler:
    # use GitHub's "revert" by creating a PR that reverts — but REST has no
    # single "revert" endpoint. We create a branch from base, apply inverse via
    # empty commit documenting the need. Prefer the compare API approach:
    # branch from parent of the merge, force base to that? That would drop the
    # bad commit only if it was the tip. Safer: open an issue-linked PR with
    # empty commit asking a human, OR use `git revert` via contents API.
    #
    # Practical path: create branch from base_ref HEAD, file a PR whose body
    # is the revert instruction + `Revert "…"` title. We attempt GitHub's
    # commits comparison and post a PR that reverts by resetting to parent
    # when the merge is HEAD.
    ref_url = f"{api_root}/repos/{repo}/git/refs"
    try:
        request("POST", ref_url, token, {
            "ref": f"refs/heads/{branch}",
            "sha": parent_sha,
        })
    except RuntimeError as exc:
        if "Reference already exists" not in str(exc) and "422" not in str(exc):
            _log({"event": "merge_audit.revert_ref_failed", "error": str(exc)[:200]})
            return None

    title = f"Revert unauthorized merge of #{pr_number}"
    body = (
        f"{BYPASS_MARKER}\n"
        f"## Auto-revert for unauthorized merge bypass\n\n"
        f"- Merged PR: #{pr_number}\n"
        f"- Merge commit: `{merge_commit_sha}`\n"
        f"- Branch tip for this PR: parent `{parent_sha[:12]}` "
        f"(drops the unauthorized merge when fast-forwarded carefully)\n"
        f"- Reason recorded: {reason[:500]}\n\n"
        f"**This does not rotate secrets.** If the merge may have exposed a "
        f"credential, rotate it first — a git revert does not undo disclosure.\n\n"
        f"Opened by gatehouse out-of-band merge-audit (Tier 1).\n"
    )
    try:
        pr = request("POST", f"{api_root}/repos/{repo}/pulls", token, {
            "title": title,
            "head": branch,
            "base": base_ref,
            "body": body,
        })
    except RuntimeError as exc:
        # Common when main has already moved past the merge: the parent branch
        # has no unique commits vs base. Delete the orphan ref so we do not
        # litter the repo on every historical re-audit.
        err = str(exc)[:200]
        _log({"event": "merge_audit.revert_pr_failed", "error": err})
        try:
            request(
                "DELETE",
                f"{api_root}/repos/{repo}/git/refs/heads/{branch}",
                token, None,
            )
            _log({"event": "merge_audit.revert_ref_cleaned", "branch": branch})
        except RuntimeError as cleanup_exc:
            _log({"event": "merge_audit.revert_ref_cleanup_failed",
                  "branch": branch, "error": str(cleanup_exc)[:200]})
        return None
    return int(pr.get("number") or 0) or None


def _record_evidence(
    repo: str,
    pr: dict,
    result: AuditResult,
    check_runs: list[dict],
    store: evidence_mod.EvidenceStore | None,
) -> None:
    """Persist gate verdicts for ≥90 days so 'why was this blocked/allowed' is answerable."""
    if store is None:
        return
    # Prefer the richer check_run list (urls/ids) over the thin CheckVerdict.
    required_names = [v.name for v in result.verdicts] if result.verdicts else list(
        (result.bypasses[0].check_conclusions if result.bypasses else {}).keys()
    )
    rich = evidence_mod.verdicts_from_check_runs(required_names, check_runs) if required_names else []
    if not rich and result.verdicts:
        rich = [
            evidence_mod.GateVerdict(
                name=v.name, required=v.required,
                status=v.status, conclusion=v.conclusion,
            )
            for v in result.verdicts
        ]
    classification = result.classification or evidence_mod.classification_from_audit(
        clean=result.clean,
        unverified=result.unverified,
        deliberate=any(b.deliberate for b in result.bypasses),
        has_bypass=bool(result.bypasses),
    )
    rec = evidence_mod.GateEvidence(
        repo=repo,
        head_sha=result.head_sha,
        pr_number=result.pr_number or None,
        merge_sha=result.merge_sha or pr.get("merge_commit_sha") or None,
        actor=result.actor or None,
        merged_at=result.merged_at or pr.get("merged_at"),
        classification=classification,
        policy_hash=result.policy_hash or None,
        notes=list(result.notes),
        verdicts=rich,
        scanner_output={
            "source": "gatehouse.merge-audit",
            "check_run_count": len(check_runs),
            "bypass_count": len(result.bypasses),
            "bypass_rules": [b.rule for b in result.bypasses],
        },
    )
    try:
        store.put(rec)
    except Exception as exc:  # noqa: BLE001 — evidence must not kill the auditor
        _log({"event": "merge_audit.evidence_write_failed",
              "repo": repo, "pr": result.pr_number, "error": str(exc)[:200]})


def run_audit_once(
    repo: str,
    token: str,
    *,
    publisher: bus.Publisher | None = None,
    gate_cfg: GateConfig | None = None,
    since_iso: str = "",
    limit: int = 20,
    revert_token: str = "",
    request: HttpFn = _gh_request,
    api_root: str = "https://api.github.com",
    base_ref: str = "main",
    now: str | None = None,
    skip_keys: set[str] | None = None,
    evidence_store: evidence_mod.EvidenceStore | None = None,
) -> list[AuditResult]:
    """Audit recent merged PRs. Side effects: bus publish + optional revert.

    `skip_keys` holds previously handled `repo#pr@head_sha` keys so a long-running
    poller does not re-publish the same bypass or re-open the same revert branch
    every interval.

    every audited PR is written to the evidence store (default path /
    GATEHOUSE_EVIDENCE_DB) with 90-day retention, including clean merges.
    """
    now = now or bus.utc_second(None)
    if gate_cfg is None:
        # Prefer local file when present (running from a checkout of the gate).
        local = os.environ.get("GATEHOUSE_REQUIRED_CHECKS", "")
        if local and os.path.exists(local):
            with open(local) as fh:
                gate_cfg = load_gate_config(fh.read())
        else:
            gate_cfg = fetch_gate_config(repo, token, ref=base_ref,
                                         request=request, api_root=api_root)

    # Open evidence store once per cycle unless the caller injects one (tests).
    own_store = False
    store = evidence_store
    if store is None and os.environ.get("GATEHOUSE_EVIDENCE_DISABLE", "").lower() not in (
        "1", "true", "yes",
    ):
        try:
            store = evidence_mod.EvidenceStore()
            own_store = True
        except Exception as exc:  # noqa: BLE001
            _log({"event": "merge_audit.evidence_open_failed", "error": str(exc)[:200]})
            store = None

    results: list[AuditResult] = []
    try:
        for pr in list_recent_merged_prs(repo, token, since_iso=since_iso,
                                         limit=limit, request=request, api_root=api_root):
            number = int(pr["number"])
            head_sha = (pr.get("head") or {}).get("sha") or ""
            key = f"{repo}#{number}@{head_sha}"
            if skip_keys is not None and key in skip_keys:
                continue
            files = list_pr_files(repo, number, token, request=request, api_root=api_root)
            checks = list_check_runs(repo, head_sha, token, request=request, api_root=api_root) if head_sha else []
            comments = list_issue_comments(repo, number, token, request=request, api_root=api_root)
            result = audit_merged_pr(
                repo=repo, pr=pr, changed_files=files, check_runs=checks,
                comments=comments, cfg=gate_cfg, now=now,
            )
            _record_evidence(repo, pr, result, checks, store)

            for rec in result.bypasses:
                alert = bypass_to_alert(rec, now=now)
                result.alerts.append(alert)
                if publisher is not None:
                    publisher.emit([alert])
                _log({
                    "event": "merge_audit.bypass",
                    "deliberate": rec.deliberate,
                    "repo": repo,
                    "pr": number,
                    "rule": rec.rule,
                    "actor": rec.actor,
                    "reason": rec.reason[:200],
                    "sha": (rec.head_sha or "")[:12],
                    "timestamp": rec.timestamp,
                })

            # Auto-revert only for unauthorized critical bypasses.
            unauthorized = [b for b in result.bypasses if not b.deliberate]
            if unauthorized and gate_cfg.auto_revert:
                tok = revert_token or os.environ.get("GATEHOUSE_REVERT_TOKEN", "")
                merge_sha = pr.get("merge_commit_sha") or head_sha
                if tok and merge_sha:
                    n = open_revert_pr(
                        repo, merge_commit_sha=merge_sha, pr_number=number,
                        token=tok, reason=unauthorized[0].reason,
                        request=request, api_root=api_root, base_ref=base_ref,
                    )
                    result.revert_pr = n
                    if n:
                        result.notes.append(f"opened auto-revert PR #{n}")

            if skip_keys is not None:
                skip_keys.add(key)
            results.append(result)
            time.sleep(0)  # hook for tests / rate limit extension
    finally:
        if own_store and store is not None:
            try:
                # Keep the window honest: prune every cycle (cheap DELETE).
                removed = store.prune()
                if removed:
                    _log({"event": "merge_audit.evidence_pruned", "removed": removed})
                store.close()
            except Exception as exc:  # noqa: BLE001
                _log({"event": "merge_audit.evidence_close_failed",
                      "error": str(exc)[:200]})
    return results


def parse_repo_specs(specs: list[str], default_ref: str = "main") -> tuple[list[str], dict[str, str]]:
    """Parse `--repo OWNER/NAME[:BASE-REF]` into (repos, {repo: base_ref}).

    The twin repo (littlewiz) gates `master` while ai-monitoring gates `main`,
    so a single shared `--base-ref` cannot express a multi-repo deployment
    . A bare `OWNER/NAME` falls back to `default_ref`.
    """
    repos: list[str] = []
    refs: dict[str, str] = {}
    for spec in specs:
        name, sep, ref = spec.rpartition(":")
        if sep and "/" in name:
            repos.append(name)
            refs[name] = ref or default_ref
        else:
            repos.append(spec)
            refs[spec] = default_ref
    return repos, refs


def _touch_heartbeat(path: str) -> None:
    """Liveness signal for the supervisor: mtime < N×interval means alive."""
    if not path:
        return
    try:
        with open(path, "a"):
            os.utime(path, None)
    except OSError as exc:
        _log({"event": "merge_audit.heartbeat_failed", "error": str(exc)[:200]})


def poll_forever(
    repos: list[str],
    token: str,
    *,
    interval_s: int = 120,
    publisher: bus.Publisher | None = None,
    base_refs: dict[str, str] | None = None,
    **kwargs: Any,
) -> None:
    """Long-running scheduler. Failure domain is this process, not GH Actions."""
    kwargs.pop("base_ref", None)  # per-repo refs win; a shared one is ambiguous
    seen: set[str] = set()
    heartbeat_file = os.environ.get("GATEHOUSE_HEARTBEAT_FILE", "")
    _touch_heartbeat(heartbeat_file)
    while True:
        for repo in repos:
            try:
                results = run_audit_once(
                    repo, token, publisher=publisher, skip_keys=seen,
                    base_ref=(base_refs or {}).get(repo, "main"), **kwargs,
                )
            except Exception as exc:  # noqa: BLE001 — never die silently
                _log({"event": "merge_audit.poll_error", "repo": repo,
                      "error": str(exc)[:300]})
                continue
            for r in results:
                _log({"event": "merge_audit.result", "repo": repo,
                      "pr": r.pr_number, "clean": r.clean,
                      "bypasses": len(r.bypasses), "notes": r.notes})
            if not results:
                _log({"event": "merge_audit.cycle_clean", "repo": repo,
                      "seen": len(seen)})
        # Cap seen set so a long-lived process does not grow forever.
        if len(seen) > 5000:
            seen = set(list(seen)[-2000:])
        _touch_heartbeat(heartbeat_file)
        time.sleep(max(15, interval_s))
