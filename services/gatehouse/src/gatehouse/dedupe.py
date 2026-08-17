"""Merging four scanners' output into one list an engineer will actually read.

Two different collapses happen here, and conflating them loses findings:

* **Identity** (`dedupe_key`) — the stable name of a finding across re-pushes
  *and across PRs of the same repo* (AC#3). Line numbers are excluded
  on purpose: adding an import at the top of a file shifts every line below
  it, and a key built on line numbers would re-alert the whole file as new.
  Identity is (pillar, finding_type, repo, path, rule, snippet digest) —
  not the PR number. The PR is an *occurrence* of the finding, counted in
  `observed_count`, and carried on `resource.ref` / `labels.pr` for action.

* **Overlap** — two scanners describing the same defect. gitleaks and semgrep
  both fire on a hardcoded credential; checkov and trivy both fire on a
  Dockerfile. Reporting it twice trains people to skim. The higher-severity
  finding wins and the loser becomes a label, never a dropped result.

Overlap is only ever collapsed *within a file and within intersecting lines*.
Two findings that merely share a rule id are not the same finding.
"""

from __future__ import annotations

import hashlib

from .models import Finding

PILLAR = "pr_security"

# Which finding types describe the same underlying defect closely enough that
# two of them on the same lines is a duplicate rather than two problems.
#
# Deliberately narrow. An earlier version had `iac_misconfig` in here, which
# meant checkov's eight independent findings on one S3 bucket — public ACL,
# no encryption, no versioning, no logging — collapsed into a single row and
# seven real misconfigurations were reported as a label. Cross-scanner overlap
# is about two tools naming one defect, not about one tool being thorough.
_OVERLAP_FAMILIES = [
    {"pr_security.secret_in_diff", "pr_security.hardcoded_secret"},
]


def dedupe_key(finding: Finding, identity_ref: str) -> str:
    """Stable identity for one finding in one repository (contract §3.1.1(a)).

    `identity_ref` is the *repo* scope (`github:owner/name`), not a PR ref.
    The same secret on five open PRs is one `dedupe_key` with five occurrences
    , so a consumer keyed on `alert_id`/`dedupe_key` cannot fan out
    into five inbox rows for one problem.

    Prose is excluded deliberately — deriving a key from a title rotates every
    key the first time someone copy-edits a rule description, which duplicates
    the entire inbox at once.
    """
    parts = [PILLAR, finding.finding_type, identity_ref, finding.path,
             finding.rule_id, finding.snippet_digest]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _family(finding_type: str) -> frozenset:
    for family in _OVERLAP_FAMILIES:
        if finding_type in family:
            return frozenset(family)
    return frozenset({finding_type})


def _overlaps(a: Finding, b: Finding) -> bool:
    # Two results from the SAME scanner are never each other's duplicate: the
    # scanner already deduped its own output, so two rows mean two problems.
    # Without this, trivy's CVEs in one lockfile (all file-level, all the same
    # finding type) would collapse to whichever CVE sorted first.
    if a.scanner == b.scanner:
        return False
    if a.path != b.path or _family(a.finding_type) != _family(b.finding_type):
        return False
    if not a.line or not b.line:  # file-level finding: same file is enough
        return True
    return a.line <= b.end_line and b.line <= a.end_line


def merge(findings: list[Finding], identity_ref: str) -> list[Finding]:
    """Collapse duplicates and overlaps. Returns findings sorted for display.

    Sort order is severity, then path, then line — the order a reviewer wants
    to work the list in, and stable so a re-push does not reshuffle the check
    output for reasons unrelated to the change.
    """
    by_key: dict[str, Finding] = {}
    for finding in findings:
        key = dedupe_key(finding, identity_ref)
        existing = by_key.get(key)
        if existing is None or finding.rank < existing.rank:
            by_key[key] = finding

    kept: list[Finding] = []
    for finding in sorted(by_key.values(), key=lambda f: (f.rank, f.path, f.line)):
        for index, existing in enumerate(kept):
            if not _overlaps(existing, finding):
                continue
            # Same defect seen twice. The first one wins (the list is already
            # severity-sorted), and the second is recorded rather than dropped:
            # "gitleaks + checkov" is a stronger signal than either alone, and
            # an engineer who greps for the losing rule id must still find it.
            also = existing.labels.get("also_found_by", "")
            names = [n for n in also.split(",") if n]
            if finding.scanner not in names:
                names.append(finding.scanner)
            kept[index] = _relabel(existing, also_found_by=",".join(names)[:128])
            break
        else:
            kept.append(finding)
    return kept


def _relabel(finding: Finding, **labels: str) -> Finding:
    merged = dict(finding.labels)
    merged.update(labels)
    return Finding(
        scanner=finding.scanner, rule_id=finding.rule_id,
        finding_type=finding.finding_type, title=finding.title,
        severity=finding.severity, path=finding.path, line=finding.line,
        end_line=finding.end_line, message=finding.message,
        remediation=finding.remediation, snippet_digest=finding.snippet_digest,
        labels=merged,
    )
