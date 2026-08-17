"""The one internal finding shape every scanner normalizes into (AIM-161).

Four scanners with four output formats converge here *before* anything else in
gatehouse runs. Dedupe, suppression, the check-run renderer and the alert
publisher all read `Finding` and never a scanner's native JSON — so adding a
fifth scanner is one adapter, not a change in five places.

Nothing in this module holds repo *content*. `snippet_digest` is a one-way
hash used for identity; the matched line itself is deliberately not a field,
because the finding outlives the ephemeral workspace and the code must not
(D4 retention rule: findings yes, code no).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# The alert contract's scale (security.alert/v1 §3.2). Kept identical to
# guardrail/bus.py so the two pillars rank the same way in one inbox.
SEVERITY_ID = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


@dataclass(frozen=True)
class Finding:
    """One normalized result from one scanner.

    `path` is repo-relative POSIX. `line` is 1-based and points at the first
    line of the match; `end_line` defaults to `line` for point findings.
    """

    scanner: str
    rule_id: str
    finding_type: str
    title: str
    severity: str
    path: str
    line: int
    end_line: int = 0
    message: str = ""
    remediation: str = ""
    # sha256 of the matched text, truncated. Identity only — see dedupe.py.
    snippet_digest: str = ""
    labels: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.end_line < self.line:
            object.__setattr__(self, "end_line", self.line)
        if self.severity not in SEVERITY_ID:
            raise ValueError(f"{self.scanner}: severity not normalized: {self.severity!r}")

    @property
    def severity_id(self) -> int:
        return SEVERITY_ID[self.severity]

    @property
    def rank(self) -> int:
        """Sort key: 0 = most severe. Used for check-run ordering."""
        return SEVERITY_ORDER.index(self.severity)


def digest(text: str) -> str:
    """Identity digest for a matched snippet — 16 hex chars, one way.

    Used instead of the snippet itself so two different secrets in one file
    stay two findings while nothing recoverable is persisted. Truncated to 16
    because this is a discriminator inside an already-scoped key (repo, path,
    rule), not a standalone credential fingerprint.
    """
    return hashlib.sha256(text.strip().encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class ScanTarget:
    """What a scan is about. Built from a webhook payload or CLI flags."""

    repo_full_name: str  # "hawikk/aim"
    pr_number: int
    base_sha: str
    head_sha: str
    installation_id: int = 0
    # Where the ephemeral clone lives during the run. Never persisted.
    workdir: str = ""
    # Head branch name and PR author login — action context on the bus (AIM-299),
    # never a monitored-person pseudonym (subject_ref stays null).
    head_ref: str = ""
    author_login: str = ""

    @property
    def resource_ref(self) -> str:
        """The alert contract's `resource.ref` for a pull request (§3.3).

        Points at the PR that just produced this emission so an analyst can
        act. Identity for *dedupe* is `identity_ref` — deliberately broader.
        """
        return f"github:{self.repo_full_name}#{self.pr_number}"

    @property
    def identity_ref(self) -> str:
        """Stable identity scope for multi-PR dedupe (AIM-299 AC#3).

        The same secret on five PRs of one repo is one issue with five
        occurrences, not five issues. PR number is an occurrence coordinate
        (resource.ref + labels.pr), not part of the finding's name.
        """
        return f"github:{self.repo_full_name}"

    @property
    def owner(self) -> str:
        return self.repo_full_name.split("/", 1)[0]
