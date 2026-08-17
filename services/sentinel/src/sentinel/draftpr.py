"""Open one draft pull request carrying a catalogue fix — or say, out loud, why not.

Board answer Q7 allows this and requires it to be opt-in and off by default, so
every step below is a gate that fails *closed and loudly*:

    enabled?  ->  repo in the config allowlist?  ->  App installed on that repo?
              ->  does the catalogue entry carry a reviewed patch?
              ->  does the patch apply cleanly at the flagged line?
              ->  draft PR, labelled, never merged

Both halves of the opt-in are required and they are deliberately different
kinds of thing. The allowlist is *ours* — it lives in `sentinel.yml`, in git,
reviewed. The installation is *theirs* — a repo admin grants it in GitHub and
can revoke it without asking us. Neither alone is consent.

The outcome of all of this is a `PROutcome`, and the important property is that
**there is no state in which nothing is said.** The ping renders the outcome in
every branch: opened, already open, not eligible, no reviewed patch, refused,
credential unavailable. "The operator turned draft PRs on and then never saw
one and never saw an error" is the exact failure this stack is built to make
impossible, and it is the easy failure to ship here.

What this module may never do, and holds no code for: merge, approve, enable
auto-merge, push to an existing branch it did not create, or write to the
default branch.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass

from . import patch as patchlib
from .github import Client, GitHubError, NotInstalled
from .patch import PatchRefused

BRANCH_PREFIX = "sentinel/fix"
# AIM-330: every autofix PR is labelled agent-generated for auditability.
# machine-generated is kept for backward compatibility with existing repo
# rules; sentinel-remediation names the system that opened it.
PR_LABELS = ("agent-generated", "machine-generated", "sentinel-remediation")
# Recognises `github:owner/repo` and `github:owner/repo#12` (contract §3.3).
_RESOURCE_REF = re.compile(r"^github:([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)(?:#(\d+))?$")
_UNSAFE_TITLE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class PROutcome:
    """What happened, in a form the renderer can print without branching on None."""

    state: str          # opened | existing | not_eligible | no_patch | unchanged | failed | guided
    note: str           # one sentence, goes verbatim into the ping
    url: str = ""
    branch: str = ""
    pr_number: int = 0
    entry_id: str = ""
    finding_link: str = ""

    @property
    def is_pr(self) -> bool:
        return self.state in ("opened", "existing")


@dataclass(frozen=True)
class RepoTarget:
    repo: str
    path: str
    line: int
    pr_number: int = 0

    @property
    def owner(self) -> str:
        return self.repo.split("/", 1)[0]


def resolve_target(alert: dict) -> RepoTarget | None:
    """The repo, file and line this alert points at, or None if it points at no repo.

    None is not a failure and is not rendered: a public S3 bucket found by the
    cloud pillar names no file, and printing "no draft PR was opened" on every
    cloud finding would train operators to skip the line that matters.
    """
    resource = alert.get("resource") or {}
    match = _RESOURCE_REF.match(str(resource.get("ref") or ""))
    if not match:
        return None
    labels = alert.get("labels") or {}
    try:
        line = int(str(labels.get("line") or "0"))
    except ValueError:
        line = 0
    return RepoTarget(repo=match.group(1), path=str(labels.get("path") or ""),
                      line=line, pr_number=int(match.group(2) or 0))


class DraftPROpener:
    """Stateless per call; holds the App client and the config allowlist.

    ``budget_seconds`` exists because this path sits *inside* the 2-minute ping
    bar. Six GitHub calls at the client's 30s timeout is three minutes of worst
    case, which would turn a slow GitHub into a late critical page — trading the
    product's core promise for a nice-to-have. When the budget runs out the PR
    is abandoned and reported as failed; the ping goes out on time with the
    copy-paste fix, which is the trade in the right direction.

    ``store`` is optional: when present, every opened PR is recorded for the
    AIM-330 fix-acceptance-rate metric (opened vs merged vs closed).
    """

    def __init__(self, cfg, client: Client | None = None, *, clock=None,
                 budget_seconds: float = 45.0, store=None):
        self.cfg = cfg
        self.client = client if client is not None else Client(
            app_id=cfg.draft_pr.app_id, private_key=cfg.draft_pr.private_key)
        self.clock = clock or time.monotonic
        self.budget_seconds = budget_seconds
        self.store = store
        self._started = 0.0

    def _deadline(self) -> None:
        if self.clock() - self._started > self.budget_seconds:
            raise GitHubError(
                f"gave up after {self.budget_seconds:.0f}s so the page would not be late")

    def maybe_open(self, *, alert: dict, proposal, incident: dict,
                   evidence_url: str = "") -> PROutcome | None:
        self._started = self.clock()
        finding_link = _finding_link(alert, evidence_url)

        # AIM-330: secret / guided classes never get an autofix PR — not even
        # when a repo is allowlisted. History rewrite requires human approval.
        if getattr(proposal, "autofix_mode", "") == "guided":
            return PROutcome(
                state="guided",
                entry_id=str(getattr(proposal, "entry_id", "") or ""),
                finding_link=finding_link,
                note=(f"guided remediation only (no autofix PR): catalogue entry "
                      f"`{proposal.entry_id or 'none'}` is rotate+purge guidance. "
                      f"History rewrite / force-push is NEVER auto-applied — a human "
                      f"with change-management approval must run those steps. "
                      f"Originating finding: {finding_link or alert.get('alert_id', '?')}."))

        target = resolve_target(alert)
        if target is None:
            return None
        if not self.cfg.draft_pr.enabled:
            return None

        # Allowlist first, before any network call. A repo we were not told to
        # touch should not even be looked up — and the operator gets the exact
        # config key to edit rather than "not eligible".
        if target.repo.lower() not in self.cfg.draft_pr.repo_set:
            return PROutcome(
                state="not_eligible",
                finding_link=finding_link,
                note=(f"no draft PR: {target.repo} is not in the draft-PR allowlist "
                      f"(`remediation.draft_pr.repos` in sentinel.yml). The fix above is "
                      f"copy-paste only for this repo."))
        if not proposal.patch:
            return PROutcome(
                state="no_patch",
                finding_link=finding_link,
                note=(f"no draft PR: the catalogue entry `{proposal.entry_id or 'none'}` has no "
                      f"reviewed patch, and sentinel does not let a model author one. Apply the "
                      f"fix above by hand."))
        try:
            clean_path = patchlib.safe_repo_path(target.path)
            # SCA findings often name the lockfile; dep-bump edits the sibling
            # manifest instead (lockfiles need package-manager regeneration).
            if (getattr(proposal.patch, "kind", "") == "bump_dep_version"
                    and not any(clean_path.endswith(s) for s in proposal.patch.path_suffixes)):
                sibling = _sibling_manifest(clean_path)
                if sibling:
                    clean_path = sibling
            patchlib.check_path_allowed(clean_path, proposal.patch)
        except PatchRefused as err:
            return PROutcome(state="no_patch", finding_link=finding_link,
                             note=f"no draft PR: {err}")

        try:
            return self._open(alert=alert, proposal=proposal, incident=incident,
                              target=target, clean_path=clean_path,
                              evidence_url=evidence_url, finding_link=finding_link)
        except NotInstalled as err:
            return PROutcome(
                state="not_eligible",
                finding_link=finding_link,
                note=(f"no draft PR: {err}. The repo is allowlisted in sentinel.yml, so this is "
                      f"the other half of the opt-in — a repo admin still has to install the "
                      f"sentinel remediation App."))
        except PatchRefused as err:
            return PROutcome(state="no_patch", finding_link=finding_link,
                             note=f"no draft PR: {err}")
        except GitHubError as err:
            # Credential revoked, key unusable, GitHub down, rate limited. The
            # ping still goes out with the copy-paste fix; this line is what
            # stops it from going out looking like a success.
            return PROutcome(
                state="failed",
                finding_link=finding_link,
                note=(f"draft PR could NOT be opened: {err}. The copy-paste fix above is "
                      f"unaffected — apply it by hand."))
        except Exception as err:  # noqa: BLE001 — a remediation bug must not lose the page
            return PROutcome(
                state="failed",
                finding_link=finding_link,
                note=(f"draft PR could NOT be opened ({type(err).__name__}: {err}). The "
                      f"copy-paste fix above is unaffected — apply it by hand."))

    # ---- the happy path, one step per gate --------------------------------

    def _open(self, *, alert, proposal, incident, target: RepoTarget, clean_path: str,
              evidence_url: str, finding_link: str = "") -> PROutcome:
        # The budget is checked between *every* step, not only before the
        # writes. Six calls at the client's 30s timeout is 180s of worst case,
        # and a check that only guards the writes would let the reads alone blow
        # through the 2-minute ping bar before the guard is ever consulted.
        # Between every call the worst case is the budget plus one timeout.
        token = self.client.token_for(target.repo)
        self._deadline()
        base_ref, base_sha = self._base(target, token)
        self._deadline()

        content, blob_sha = self.client.get_file(target.repo, clean_path, base_ref, token=token)
        self._deadline()
        labels = alert.get("labels") or {}
        result = patchlib.apply(proposal.patch, content, target.line, path=clean_path,
                                labels=labels)
        if not result.changed:
            # The branch already has the fix. Opening an empty PR would be noise
            # with a merge button on it; saying so is the useful answer.
            return PROutcome(
                state="unchanged",
                finding_link=finding_link,
                note=(f"no draft PR: {result.note} in `{base_ref}` — the finding may be stale, "
                      f"or already fixed since it was scanned."))

        branch = _branch_name(target.repo, base_ref, clean_path, proposal.entry_id)
        existing = self.client.open_pr_for_branch(target.repo, target.owner, branch, token=token)
        if existing:
            return PROutcome(state="existing", url=str(existing.get("html_url") or ""),
                             branch=branch, finding_link=finding_link,
                             pr_number=int(existing.get("number") or 0),
                             entry_id=str(proposal.entry_id or ""),
                             note=(f"draft PR already open for this fix: "
                                   f"{existing.get('html_url')} — not opening a second."))

        self._deadline()
        if self.client.create_branch(target.repo, branch, base_sha, token=token):
            self.client.put_file(
                target.repo, clean_path, token=token, branch=branch, content=result.content,
                blob_sha=blob_sha,
                message=_commit_message(proposal, result, clean_path, incident, alert))
        else:
            # The branch exists with no open PR: a previous run was interrupted
            # between the push and the PR, or a human closed the PR and kept the
            # branch. Compare rather than re-patch — the earlier commit shifted
            # the line numbers the finding refers to, so re-running the patcher
            # against this content would be applying a rule to coordinates that
            # no longer mean what they meant.
            branch_content, branch_sha = self.client.get_file(
                target.repo, clean_path, branch, token=token)
            if branch_content != result.content:
                self.client.put_file(
                    target.repo, clean_path, token=token, branch=branch,
                    content=result.content, blob_sha=branch_sha,
                    message=_commit_message(proposal, result, clean_path, incident, alert))
        self._deadline()
        pull = self.client.create_pull(
            target.repo, token=token,
            title=_title(proposal, clean_path),
            head=branch, base=base_ref,
            body=_body(alert=alert, proposal=proposal, incident=incident, result=result,
                       path=clean_path, evidence_url=evidence_url, base_ref=base_ref,
                       finding_link=finding_link))
        number = int(pull.get("number") or 0)
        url = str(pull.get("html_url") or "")
        if number:
            try:
                self.client.add_labels(target.repo, number, list(PR_LABELS), token=token)
            except GitHubError:
                # Best effort: the PR exists and is a draft either way. Failing
                # the whole outcome over a missing label would report a success
                # as a failure, which is its own kind of lie.
                pass
        outcome = PROutcome(
            state="opened", url=url, branch=branch, pr_number=number,
            entry_id=str(proposal.entry_id or ""), finding_link=finding_link,
            note=(f"draft PR opened: {url} — {result.note}. It is a DRAFT and is "
                  f"not auto-merged; a human reviews and merges it. "
                  f"Labels: {', '.join(PR_LABELS)}. Originating finding: "
                  f"{finding_link or alert.get('alert_id', '?')}."))
        self._record_opened(alert=alert, proposal=proposal, incident=incident,
                            target=target, outcome=outcome)
        return outcome

    def _record_opened(self, *, alert, proposal, incident, target: RepoTarget,
                       outcome: PROutcome) -> None:
        """Persist the opened PR for acceptance-rate tracking (AIM-330)."""
        if self.store is None or not outcome.url:
            return
        try:
            self.store.record_autofix_pr(
                repo=target.repo,
                pr_number=outcome.pr_number,
                pr_url=outcome.url,
                branch=outcome.branch,
                alert_id=str(alert.get("alert_id") or ""),
                finding_type=str(alert.get("finding_type") or ""),
                entry_id=str(proposal.entry_id or ""),
                incident_id=str(incident.get("incident_id") or ""),
                finding_link=outcome.finding_link,
            )
        except Exception:  # noqa: BLE001 — metric must not fail the page
            pass

    def _base(self, target: RepoTarget, token: str) -> tuple[str, str]:
        """The branch this fix belongs on.

        For a finding raised against a pull request, that is the PR's own head
        branch — the misconfiguration is in the change under review and may not
        exist on the default branch at all. Committing it to the default branch
        instead would "fix" something that was never broken there and leave the
        actual PR still failing.
        """
        if target.pr_number:
            pull = self.client.pull_request(target.repo, target.pr_number, token=token)
            head = (pull or {}).get("head") or {}
            head_repo = str((head.get("repo") or {}).get("full_name") or "")
            if str(pull.get("state") or "") != "open":
                raise PatchRefused(
                    f"{target.repo}#{target.pr_number} is not open; there is nothing to fix on it")
            if head_repo and head_repo.lower() != target.repo.lower():
                raise PatchRefused(
                    f"{target.repo}#{target.pr_number} comes from the fork {head_repo}; sentinel "
                    f"has no write access to a fork and will not ask for one")
            ref, sha = str(head.get("ref") or ""), str(head.get("sha") or "")
            if not ref or not sha:
                raise GitHubError(f"could not read the head branch of {target.repo}"
                                  f"#{target.pr_number}")
            return ref, sha
        info = self.client.repo_info(target.repo, token=token)
        ref = str(info.get("default_branch") or "")
        if not ref:
            raise GitHubError(f"could not read the default branch of {target.repo}")
        return ref, self.client.ref_sha(target.repo, f"heads/{ref}", token=token)


# Lockfile basename → preferred sibling manifest for dep-bump (AIM-330).
_LOCKFILE_TO_MANIFEST = {
    "package-lock.json": "package.json",
    "yarn.lock": "package.json",
    "pnpm-lock.yaml": "package.json",
    "npm-shrinkwrap.json": "package.json",
    "poetry.lock": "pyproject.toml",
    "pipfile.lock": "Pipfile",
}


def _sibling_manifest(lock_path: str) -> str | None:
    """If the finding points at a lockfile, return the co-located manifest path."""
    base = lock_path.rsplit("/", 1)[-1].lower()
    manifest = _LOCKFILE_TO_MANIFEST.get(base)
    if not manifest:
        return None
    if "/" in lock_path:
        return lock_path.rsplit("/", 1)[0] + "/" + manifest
    return manifest


def _branch_name(repo: str, base_ref: str, path: str, entry_id: str) -> str:
    """Deterministic, so a recurring finding re-finds its own branch instead of
    opening a new PR every time the alert is republished."""
    digest = hashlib.sha256(f"{repo}|{base_ref}|{path}|{entry_id}".encode()).hexdigest()[:12]
    slug = re.sub(r"[^a-z0-9-]+", "-", (entry_id or "fix").lower()).strip("-") or "fix"
    return f"{BRANCH_PREFIX}/{slug}-{digest}"


def _title(proposal, path: str) -> str:
    return _clean(f"[sentinel] {proposal.title} in {path}")[:120]


def _commit_message(proposal, result, path: str, incident: dict, alert: dict | None = None) -> str:
    alert = alert or {}
    return _clean(
        f"{proposal.title}: {result.note} in {path}\n\n"
        f"Applied from the sentinel remediation catalogue entry `{proposal.entry_id}`.\n"
        f"Incident {incident.get('incident_id', '?')}. "
        f"Originating alert {alert.get('alert_id', '?')}. "
        f"Agent-generated; review before merge.")[:2000]


def _finding_link(alert: dict, evidence_url: str = "") -> str:
    """Stable audit pointer back to the originating finding."""
    if evidence_url:
        return evidence_url
    uri = str((alert.get("evidence") or {}).get("source_uri") or "").strip()
    if uri:
        return uri
    return str(alert.get("alert_id") or "")


def _changelog_excerpt(alert: dict) -> str:
    """Best-effort changelog / advisory excerpt for dep-bump PRs (AIM-330)."""
    labels = alert.get("labels") or {}
    evidence = alert.get("evidence") or {}
    bits = []
    cve = str(labels.get("cve") or "").strip()
    if cve:
        bits.append(f"**Advisory:** {cve}")
    pkg = str(labels.get("pkg") or "").strip()
    installed = str(labels.get("installed_version") or "").strip()
    fixed = str(labels.get("fixed_version") or "").strip()
    if pkg:
        bits.append(f"**Package:** `{pkg}`"
                    + (f" `{installed}` → `{fixed}`" if fixed else ""))
    summary = str(evidence.get("summary") or alert.get("title") or "").strip()
    if summary:
        bits.append(f"**Excerpt:** {_clean(summary)[:500]}")
    message = str(alert.get("title") or "")
    # Prefer a longer advisory blurb when the publisher put one on the alert.
    detail = str((alert.get("evidence") or {}).get("detail") or "").strip()
    if not detail:
        # Some publishers fold the advisory into remediation_hint.
        detail = str(alert.get("remediation_hint") or "").strip()
    if detail:
        bits.append(f"**Notes:** {_clean(detail)[:600]}")
    if not bits:
        bits.append("_No advisory excerpt was attached to the finding; check the CVE/OSV page._")
    return "\n".join(bits)


def _test_status_section(alert: dict, proposal) -> str:
    """What a reviewer should expect for CI / tests on this autofix PR."""
    if getattr(proposal, "entry_id", "") == "sca-dep-bump" or (
            getattr(proposal.patch, "kind", "") == "bump_dep_version"):
        return (
            "### Test status\n\n"
            "- **Status:** pending CI on this draft branch (not run by sentinel).\n"
            "- After the lockfile is refreshed (`npm install` / `poetry lock` / …), "
            "push the lockfile update and wait for the repo's required checks.\n"
            "- Do **not** merge while unit/integration checks are red — a green "
            "version bump with a red suite is still a broken release.\n"
            "- Reachability (if present): "
            f"`{(alert.get('labels') or {}).get('reachability', 'unknown')}`."
        )
    return (
        "### Test status\n\n"
        "- **Status:** pending CI on this draft branch (not run by sentinel).\n"
        "- Merge only after the repository's required checks are green on this head."
    )


def _body(*, alert, proposal, incident, result, path: str, evidence_url: str,
          base_ref: str, finding_link: str = "") -> str:
    """The PR description. Written so a reviewer can answer "should I merge
    this?" without leaving the page: what was found, what changed, what it might
    break, and where the patch came from."""
    link = finding_link or _finding_link(alert, evidence_url)
    lines = [
        "## Automated remediation — review before merging",
        "",
        f"**Labels:** `{'`, `'.join(PR_LABELS)}` (agent-generated autofix)",
        f"**Finding:** {_clean(str(alert.get('title') or 'security finding'))} "
        f"(`{_clean(str(alert.get('finding_type') or '?'))}`, "
        f"severity **{_clean(str(alert.get('severity') or '?'))}**)",
        f"**Originating finding:** `{_clean(link)}`",
        f"**Alert id:** `{_clean(str(alert.get('alert_id') or '?'))}`",
        f"**Change:** {result.note} in `{path}`, on `{base_ref}`.",
        "",
        proposal.explanation or "",
    ]
    if proposal.caution:
        lines += ["", f"> ⚠️ **Before you merge:** {proposal.caution}"]
    if evidence_url:
        lines += ["", f"[Full finding and evidence]({evidence_url})"]
    # Dep-bump ACs: changelog excerpt + test status on every SCA fix PR.
    if (getattr(proposal, "entry_id", "") == "sca-dep-bump"
            or getattr(getattr(proposal, "patch", None), "kind", "") == "bump_dep_version"):
        lines += ["", "### Changelog / advisory excerpt", "", _changelog_excerpt(alert)]
    lines += ["", _test_status_section(alert, proposal)]
    lines += [
        "",
        "---",
        "",
        "### Where this diff came from",
        "",
        f"The catalogue entry `{proposal.entry_id}` in "
        f"`services/sentinel/src/sentinel/catalogue/remediation.yml`, applied by "
        f"`services/sentinel/src/sentinel/patch.py`. **No part of this diff was written by "
        f"a language model** — the model that triaged the finding writes the explanation in "
        f"the Slack ping and nothing else. Changing what this PR can do means changing a "
        f"reviewed file in `ai-monitoring`, in a PR of its own.",
        "",
        "This PR is a **draft**, is never auto-merged, and the App that opened it holds "
        "`contents: write` and `pull_requests: write` on this repository only.",
        "",
        f"<sub>sentinel · agent-generated · incident "
        f"`{_clean(str(incident.get('incident_id', '?')))}` · "
        f"alert `{_clean(str(alert.get('alert_id') or '?'))}` · "
        f"finding `{_clean(link)}`</sub>",
    ]
    return "\n".join(lines)


def _clean(text: str) -> str:
    """Alert titles are publisher-controlled. Strip control characters and
    collapse newlines so a crafted title cannot forge structure in a PR title,
    a commit message header or a body section."""
    return _UNSAFE_TITLE.sub(" ", str(text)).replace("\n", " ").strip()
