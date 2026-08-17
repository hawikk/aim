"""One-click suggested fixes on PR findings (AIM-234 / CodeRabbit parity).

For each corroborated scanner finding that has a reviewed catalogue patch:

1. Apply the patch to the file in the ephemeral workspace (in memory).
2. Self-scan the result with the *same* scanner that raised the finding.
   A fix that introduces a new finding, or fails to clear the original, is
   refused — that is a defect of this feature, not of the PR.
3. If the changed span is at or under the documented size threshold, post a
   GitHub ```suggestion review comment (committable in one click).
4. If it is larger, and the repo is on the draft-PR allowlist (same gate as
   AIM-185), record a draft-PR note that the summary comment can link.

Advisory only. Suggestions never change the check conclusion and never use
`REQUEST_CHANGES`. `ai_review.blocking` is untouched.

Default on; a repo opts out with `suggested_fixes.enabled: false` in
`.gatehouse.yml` (read from the base branch, like the rest of that file).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from . import checkrun, fix_patch
from .fix_patch import PatchRefused, PatchResult, PatchSpec
from .models import Finding, SEVERITY_ORDER
from .scanners import run_all
from .scanners.base import log

CATALOGUE_PATH = Path(__file__).resolve().parent / "catalogue" / "fixes.yml"

# Documented thresholds. A suggestion replaces a contiguous span on one file;
# beyond this the human should review a full draft PR instead of a one-click
# inline commit. Counts are on the *replacement* body (what lands in the
# ```suggestion fence), not on the whole file.
MAX_SUGGESTION_LINES = int(os.environ.get("GATEHOUSE_SUGGEST_MAX_LINES", "5"))
MAX_SUGGESTION_CHARS = int(os.environ.get("GATEHOUSE_SUGGEST_MAX_CHARS", "800"))

# Same shape of gate as AIM-185: a comma-separated owner/repo allowlist. Gatehouse
# never opens the draft PR itself (contents:read only); it only *links* the
# path when the operator has opted the repo into sentinel draft-PR remediation.
DRAFT_PR_REPOS_ENV = "GATEHOUSE_DRAFT_PR_REPOS"

# Cap how many review comments we post per PR so a noisy scan cannot flood
# the Files changed tab. The rest still appear as annotations + the summary.
MAX_SUGGESTIONS_PER_PR = int(os.environ.get("GATEHOUSE_SUGGEST_MAX_PER_PR", "20"))

MARKER = "<!-- gatehouse:suggest:v1 -->"


@dataclass(frozen=True)
class FixEntry:
    id: str
    finding_type: re.Pattern[str]
    label_patterns: dict[str, re.Pattern[str]]
    title: str
    summary: str
    patch: PatchSpec


@dataclass
class FixCatalogue:
    entries: list[FixEntry] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | str = CATALOGUE_PATH) -> "FixCatalogue":
        with open(path) as fh:
            doc = yaml.safe_load(fh) or {}
        cat = cls()
        for raw in doc.get("entries") or []:
            entry_id = str(raw.get("id") or "?")
            pattern = re.compile(f"^(?:{raw['finding_type']})$")
            label_patterns = {
                str(k): re.compile(f"^(?:{v})$")
                for k, v in ((raw.get("when") or {}).get("labels") or {}).items()}
            patch = PatchSpec.parse(raw["patch"], entry_id=entry_id)
            cat.entries.append(FixEntry(
                id=entry_id, finding_type=pattern, label_patterns=label_patterns,
                title=str(raw.get("title") or "Suggested fix"),
                summary=str(raw.get("summary") or patch.summary or ""),
                patch=patch,
            ))
        return cat

    def match(self, finding: Finding) -> FixEntry | None:
        labels = finding.labels or {}
        for entry in self.entries:
            if not entry.finding_type.match(finding.finding_type or ""):
                continue
            if all(p.match(str(labels.get(key, ""))) for key, p in entry.label_patterns.items()):
                return entry
        return None


@dataclass(frozen=True)
class SuggestedFix:
    """One finding's remediation outcome, ready to render or post."""

    finding: Finding
    entry_id: str
    title: str
    mode: str                 # suggestion | draft_pr | refused
    note: str
    path: str = ""
    start_line: int = 0
    end_line: int = 0
    replacement: str = ""
    review_body: str = ""
    draft_pr_eligible: bool = False

    @property
    def is_suggestion(self) -> bool:
        return self.mode == "suggestion"

    @property
    def is_draft_pr(self) -> bool:
        return self.mode == "draft_pr"


SelfScanFn = Callable[[str, Finding, str], tuple[bool, str]]


def draft_pr_allowlist(env: dict[str, str] | None = None) -> frozenset[str]:
    """Repos on the AIM-185 draft-PR allowlist, mirrored into gatehouse env.

    Empty means "no repo is opted in" — fail closed, same as sentinel when
    `remediation.draft_pr.repos` is empty.
    """
    env = env if env is not None else os.environ
    raw = env.get(DRAFT_PR_REPOS_ENV, "") or ""
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def is_small(result: PatchResult) -> bool:
    text = "\n".join(result.replacement_lines)
    line_count = max(1, len(result.replacement_lines))
    # Insertion suggestions rewrite the header + new attribute as two lines;
    # still well under the threshold. A multi-line RHS is already refused by
    # the patcher, so the line count here is the true size of the commit.
    return line_count <= MAX_SUGGESTION_LINES and len(text) <= MAX_SUGGESTION_CHARS


def _finding_key(f: Finding) -> tuple[str, int, str]:
    return (f.rule_id, f.line, f.snippet_digest)


def default_self_scan(repo_dir: str, finding: Finding, fixed_content: str) -> tuple[bool, str]:
    """Re-run the originating scanner on the patched file. Fail closed.

    Baseline-scans the original content first, then overwrites with the fix,
    re-scans, and restores. A fix must clear the original rule and must not
    introduce any *new* finding at equal-or-higher severity on the same path.
    """
    if finding.scanner in ("", "ai-review"):
        return False, "suggestions are only for corroborated scanner findings"
    try:
        clean = fix_patch.safe_repo_path(finding.path)
    except PatchRefused as err:
        return False, str(err)
    abs_path = os.path.join(repo_dir, clean)
    if not os.path.isfile(abs_path):
        return False, f"{clean} is not a file in the workspace"
    try:
        original = Path(abs_path).read_text(encoding="utf-8", errors="replace")
    except OSError as err:
        return False, f"could not read {clean}: {err}"

    try:
        baseline_outcomes = run_all(repo_dir, [clean], enabled=[finding.scanner])
    except Exception as err:  # noqa: BLE001
        return False, f"baseline self-scan crashed: {type(err).__name__}: {err}"
    if not baseline_outcomes or baseline_outcomes[0].error or not baseline_outcomes[0].ok:
        err = (baseline_outcomes[0].error if baseline_outcomes else "no outcome")
        return False, f"baseline self-scan incomplete: {err or 'scanner failed'}"
    baseline_keys = {
        _finding_key(f) for f in baseline_outcomes[0].findings if f.path == clean
    }

    try:
        Path(abs_path).write_text(fixed_content, encoding="utf-8")
    except OSError as err:
        return False, f"could not write fix for self-scan: {err}"

    try:
        outcomes = run_all(repo_dir, [clean], enabled=[finding.scanner])
    except Exception as err:  # noqa: BLE001 — self-scan must never crash the report
        return False, f"self-scan crashed: {type(err).__name__}: {err}"
    finally:
        try:
            Path(abs_path).write_text(original, encoding="utf-8")
        except OSError:
            pass

    if not outcomes:
        return False, "self-scan produced no outcome"
    outcome = outcomes[0]
    if outcome.error or not outcome.ok:
        return False, f"self-scan incomplete: {outcome.error or 'scanner failed'}"

    remaining = [f for f in outcome.findings
                 if f.path == clean and f.rule_id == finding.rule_id]
    if remaining:
        return False, f"self-scan still reports {finding.rule_id} on {clean}"

    original_rank = SEVERITY_ORDER.index(finding.severity)
    new_regressions = [
        f for f in outcome.findings
        if f.path == clean
        and _finding_key(f) not in baseline_keys
        and SEVERITY_ORDER.index(f.severity) <= original_rank
    ]
    if new_regressions:
        sample = new_regressions[0]
        return False, (f"self-scan introduced {sample.rule_id} ({sample.severity}) "
                       f"on {clean} — refusing to post the fix")
    return True, "self-scan cleared the finding"


def build_review_body(*, entry: FixEntry, result: PatchResult, finding: Finding) -> str:
    """Markdown for a PR review comment, including the committable suggestion."""
    lines = [
        MARKER,
        f"**Suggested fix** — {checkrun.md(entry.title, 120)}",
        "",
        f"`{checkrun.md(finding.rule_id, 60)}` · {checkrun.md(result.note, 200)}",
        "",
        "```suggestion",
        *result.replacement_lines,
        "```",
        "",
        "<sub>Advisory only — does not fail this check. Catalogue entry "
        f"`{checkrun.md(entry.id, 40)}`; self-scanned with `{finding.scanner}` before posting. "
        "Commit the suggestion from the Files changed tab.</sub>",
    ]
    return "\n".join(lines)


def propose_for_finding(
    finding: Finding, *, repo_dir: str, catalogue: FixCatalogue,
    draft_repos: frozenset[str], repo_full_name: str,
    self_scan: SelfScanFn = default_self_scan,
) -> SuggestedFix | None:
    """Build a suggestion (or draft-PR note) for one finding, or None if no entry."""
    if finding.scanner == "ai-review":
        # AIM-162: model findings are advisory and untrusted as a source of
        # machine-applied edits. Only corroborated scanner findings get a fix.
        return None
    entry = catalogue.match(finding)
    if entry is None:
        return None

    try:
        clean = fix_patch.safe_repo_path(finding.path)
        abs_path = os.path.join(repo_dir, clean)
        content = Path(abs_path).read_text(encoding="utf-8", errors="replace")
        result = fix_patch.apply(entry.patch, content, finding.line or 1, path=clean)
    except (PatchRefused, OSError, ValueError) as err:
        return SuggestedFix(
            finding=finding, entry_id=entry.id, title=entry.title, mode="refused",
            note=str(err)[:300], path=finding.path)

    if not result.changed:
        return SuggestedFix(
            finding=finding, entry_id=entry.id, title=entry.title, mode="refused",
            note=result.note, path=clean)

    ok, scan_note = self_scan(repo_dir, finding, result.content)
    if not ok:
        return SuggestedFix(
            finding=finding, entry_id=entry.id, title=entry.title, mode="refused",
            note=f"self-scan refused: {scan_note}", path=clean)

    eligible = repo_full_name.lower() in draft_repos
    if is_small(result):
        return SuggestedFix(
            finding=finding, entry_id=entry.id, title=entry.title, mode="suggestion",
            note=result.note, path=clean,
            start_line=result.start_line, end_line=result.end_line,
            replacement="\n".join(result.replacement_lines),
            review_body=build_review_body(entry=entry, result=result, finding=finding),
            draft_pr_eligible=eligible)

    if eligible:
        return SuggestedFix(
            finding=finding, entry_id=entry.id, title=entry.title, mode="draft_pr",
            note=(f"fix is {len(result.replacement_lines)} line(s) "
                  f"(threshold {MAX_SUGGESTION_LINES}); sentinel draft-PR path "
                  f"is enabled for {repo_full_name}"),
            path=clean, draft_pr_eligible=True)

    return SuggestedFix(
        finding=finding, entry_id=entry.id, title=entry.title, mode="refused",
        note=(f"fix exceeds the inline threshold ({MAX_SUGGESTION_LINES} lines / "
              f"{MAX_SUGGESTION_CHARS} chars) and this repo is not on the draft-PR "
              f"allowlist (`{DRAFT_PR_REPOS_ENV}` / sentinel `remediation.draft_pr.repos`)"),
        path=clean, draft_pr_eligible=False)


def propose(
    findings: list[Finding], *, repo_dir: str, repo_full_name: str,
    enabled: bool = True, catalogue: FixCatalogue | None = None,
    draft_repos: frozenset[str] | None = None,
    self_scan: SelfScanFn = default_self_scan,
) -> list[SuggestedFix]:
    """Build suggested fixes for every matching finding. Never raises."""
    if not enabled:
        return []
    try:
        catalogue = catalogue or FixCatalogue.load()
    except Exception as err:  # noqa: BLE001
        log({"event": "gatehouse.suggest.catalogue_failed", "error": str(err)[:200]})
        return []
    draft_repos = draft_repos if draft_repos is not None else draft_pr_allowlist()
    out: list[SuggestedFix] = []
    for finding in findings:
        if finding.scanner == "ai-review":
            continue
        try:
            fix = propose_for_finding(
                finding, repo_dir=repo_dir, catalogue=catalogue,
                draft_repos=draft_repos, repo_full_name=repo_full_name,
                self_scan=self_scan)
        except Exception as err:  # noqa: BLE001 — one bad finding must not kill the rest
            log({"event": "gatehouse.suggest.failed", "rule": finding.rule_id,
                 "error": f"{type(err).__name__}: {err}"[:200]})
            continue
        if fix is not None:
            out.append(fix)
    return out


def summary_section(fixes: list[SuggestedFix]) -> str:
    """Markdown block appended to the check-run / PR comment summary."""
    suggestions = [f for f in fixes if f.is_suggestion]
    draft = [f for f in fixes if f.is_draft_pr]
    if not suggestions and not draft:
        return ""
    lines = ["\n**One-click fixes** (advisory — never block a merge)\n"]
    if suggestions:
        lines.append(
            f"{len(suggestions)} finding(s) have a committable "
            f"[suggestion](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/"
            f"reviewing-changes-in-pull-requests/incorporating-feedback-in-your-pull-request"
            f"#applying-suggested-changes) on the **Files changed** tab.")
        for fix in suggestions[:MAX_SUGGESTIONS_PER_PR]:
            loc = f"{checkrun.md(fix.path, 80)}:{fix.start_line}"
            lines.append(
                f"- ✅ `{checkrun.md(fix.finding.rule_id, 50)}` at {loc} — "
                f"{checkrun.md(fix.note, 160)}")
    if draft:
        lines.append(
            f"\n{len(draft)} larger fix(es) exceed the inline threshold "
            f"({MAX_SUGGESTION_LINES} lines / {MAX_SUGGESTION_CHARS} chars) and are "
            f"routed to the **sentinel draft-PR** path (AIM-185 opt-in):")
        for fix in draft[:MAX_SUGGESTIONS_PER_PR]:
            loc = checkrun.md(fix.path, 80) if fix.path else "?"
            lines.append(
                f"- 📝 `{checkrun.md(fix.finding.rule_id, 50)}` at {loc} — "
                f"{checkrun.md(fix.note, 200)}")
    lines.append(
        "\n<sub>Suggested fixes are self-scanned with the same scanner before posting. "
        f"Thresholds: ≤{MAX_SUGGESTION_LINES} lines and ≤{MAX_SUGGESTION_CHARS} chars "
        "for ```suggestion blocks; larger fixes need the draft-PR allowlist. "
        "Opt out per repo with `suggested_fixes.enabled: false` in `.gatehouse.yml`.</sub>")
    return "\n".join(lines)


def review_comments(fixes: list[SuggestedFix]) -> list[dict]:
    """GitHub pull-request review comment bodies for the small suggestions."""
    comments = []
    for fix in fixes:
        if not fix.is_suggestion or not fix.review_body:
            continue
        item: dict = {
            "path": fix.path,
            "line": fix.end_line or fix.start_line or fix.finding.line or 1,
            "side": "RIGHT",
            "body": fix.review_body,
        }
        # Multi-line suggestions need start_line; single-line must omit it
        # (GitHub 422s when start_line == line).
        if fix.start_line and fix.end_line and fix.start_line < fix.end_line:
            item["start_line"] = fix.start_line
            item["start_side"] = "RIGHT"
        comments.append(item)
        if len(comments) >= MAX_SUGGESTIONS_PER_PR:
            break
    return comments
