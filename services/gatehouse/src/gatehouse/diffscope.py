"""What the PR actually changed — the scope every scanner is held to.

Two jobs, and they are different:

* **file scope** — which files to hand the scanners. Running semgrep over a
  200k-file monorepo on every push is how a PR bot earns a 20-minute p95 and
  gets turned off.
* **line scope** — which findings to report. A rule that fires on line 900 of a
  file whose PR only touched line 12 is a pre-existing finding. Reporting it
  blocks a PR for something its author did not do, and that is the single
  fastest way to lose developer trust in a security gate.

Line scope is computed from `git diff --unified=0`, which gives exact added-line
ranges rather than the ±3 lines of context a default diff would blur in.

The base is the **merge base**, not the base branch tip. If main moved forward
after the PR was opened, diffing against the tip would attribute every commit
that landed on main in the meantime to this PR.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .workspace import git

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass
class DiffScope:
    """Changed files at head, and the line ranges added in each."""

    # path -> [(start, end)] of lines that exist at head and are new in this PR.
    added_lines: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    # Paths removed by the PR. Never scanned; kept so trivy can skip a deleted
    # lockfile instead of failing on a missing path.
    deleted: list[str] = field(default_factory=list)

    @property
    def paths(self) -> list[str]:
        return sorted(self.added_lines)

    def touches(self, path: str, line: int, end_line: int | None = None) -> bool:
        """Does [line, end_line] intersect anything this PR added to `path`?

        A finding with no usable line (0) is treated as file-level: if the file
        was touched at all, the finding is in scope. That is deliberate for
        trivy, whose dependency findings belong to a manifest rather than to a
        line.
        """
        ranges = self.added_lines.get(path)
        if ranges is None:
            return False
        if not line:
            return True
        end = end_line or line
        return any(start <= end and line <= stop for start, stop in ranges)


def merge_base(repo_dir: str, base_ref: str = "refs/gatehouse/base",
               head_ref: str = "refs/gatehouse/head") -> str:
    proc = git(["merge-base", base_ref, head_ref], cwd=repo_dir, check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    # No common ancestor (force-pushed base, or a shallow fetch that did not
    # reach one). Fall back to the base ref itself: a superset of the real diff
    # is noisy, but silently scoping to nothing would report a dirty PR clean.
    return base_ref


def compute(repo_dir: str, *, base: str, head: str = "HEAD") -> DiffScope:
    """Parse `git diff --unified=0 base head` into a DiffScope."""
    proc = git(
        ["diff", "--unified=0", "--no-color", "--no-renames", "--diff-filter=ACMRT",
         base, head],
        cwd=repo_dir,
    )
    scope = DiffScope()
    current: str | None = None
    for raw in proc.stdout.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            current = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            if current:
                scope.added_lines.setdefault(current, [])
            continue
        if current and raw.startswith("@@"):
            match = _HUNK.match(raw)
            if not match:
                continue
            start = int(match.group(1))
            count = int(match.group(2) or "1")
            if count == 0:  # pure deletion hunk: nothing added at head
                continue
            scope.added_lines[current].append((start, start + count - 1))

    deleted = git(
        ["diff", "--name-only", "--diff-filter=D", base, head], cwd=repo_dir)
    scope.deleted = [p for p in deleted.stdout.splitlines() if p]
    # A file can appear with an empty range list (mode change only). Drop it —
    # there is nothing new to scan and nothing new to report.
    scope.added_lines = {p: r for p, r in scope.added_lines.items() if r}
    return scope
