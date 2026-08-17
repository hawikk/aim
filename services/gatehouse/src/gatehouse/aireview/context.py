"""The review bundle: the smallest slice of the PR a model can reason about.

What leaves the box is the trust boundary of the whole AI reviewer (AIM-162 /
AIM-233), so it is stated precisely:

1. **Diff slice** — the added hunks of each reviewable file, plus a
   configurable window of surrounding lines, capped per file and in total.
2. **Repo-graph slice (AIM-233)** — for each symbol the PR touched, the
   *signatures* of its callers and callees (no function bodies), also capped.
   This is the Greptile-style cross-file context without sending the repo.

No whole files, no history, no neighbouring file bodies the diff does not
touch. The caps exist because "send the model some context" otherwise becomes
"send the model the repo" one large generated file at a time.

Files that cannot carry a finding worth a model's time are skipped by path
heuristic: vendored trees, lockfiles, minified assets, generated code. Binary
files are skipped on content (a NUL in the first chunk). Every skip and every
truncation is recorded in the stats, because a bundle that quietly dropped the
one file that mattered would produce a clean-looking review of code nobody
looked at — the same lie a crashed scanner tells, one layer up.

Lines are numbered and added lines are prefixed `+`, which is what lets the
model anchor findings to exact lines *and* lets `review.py` verify those
anchors against the real diff afterwards.
"""

from __future__ import annotations

import os

from ..diffscope import DiffScope

DEFAULT_CONTEXT_LINES = 20
DEFAULT_MAX_FILE_BYTES = 8 * 1024
DEFAULT_MAX_TOTAL_BYTES = 96 * 1024
# Graph is optional and minority: stays inside the same total hard cap.
DEFAULT_MAX_GRAPH_BYTES = 16 * 1024

# Path heuristics for files a reviewer (human or model) would also skip.
_SKIP_DIRS = {"vendor", "vendors", "node_modules", "third_party", "dist",
              "build", "generated", ".venv"}
_SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
               "pipfile.lock", "cargo.lock", "composer.lock", "gemfile.lock",
               "go.sum"}
_SKIP_SUFFIXES = (".lock", ".min.js", ".min.css", ".pb.go", ".pb.cc", ".pb.h",
                  ".generated.ts", ".generated.js")


def _skip_reason(path: str) -> str:
    parts = path.split("/")
    name = parts[-1].lower()
    if any(part in _SKIP_DIRS for part in parts[:-1]):
        return "vendored or generated directory"
    if name in _SKIP_NAMES or name.endswith(_SKIP_SUFFIXES):
        return "lockfile, minified or generated file"
    return ""


def _read_text(repo_dir: str, path: str) -> str | None:
    """Read the file at head. None means binary/unreadable — skip it."""
    try:
        with open(os.path.join(repo_dir, path), "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if b"\0" in raw[:8192]:
        return None
    return raw.decode("utf-8", "replace")


def _section(path: str, lines: list[str], ranges: list[tuple[int, int]],
             context_lines: int) -> str:
    """One file's slice of the bundle: added ranges widened by context.

    Overlapping windows merge, so two hunks three lines apart are one section
    rather than two overlapping ones with duplicated line numbers.
    """
    total = len(lines)
    windows: list[list[int]] = []
    for start, end in ranges:
        lo, hi = max(1, start - context_lines), min(total, end + context_lines)
        if windows and lo <= windows[-1][1] + 1:
            windows[-1][1] = max(windows[-1][1], hi)
        else:
            windows.append([lo, hi])

    added = set()
    for start, end in ranges:
        added.update(range(start, end + 1))

    out = [f"## File: {path} (added lines: "
           + ", ".join(f"{a}-{b}" if a != b else str(a) for a, b in ranges) + ")"]
    for lo, hi in windows:
        for number in range(lo, hi + 1):
            marker = "+" if number in added else " "
            out.append(f"{marker} {number:>4} | {lines[number - 1]}")
    return "\n".join(out)


def _empty_graph_stats() -> dict:
    return {
        "graph_bytes": 0,
        "graph_symbols": 0,
        "graph_edges": 0,
        "graph_files_indexed": 0,
        "graph_index_truncated": False,
        "graph_skipped": [],
        "graph_cap_hit": False,
        "graph_enabled": False,
    }


def build_bundle(repo_dir: str, scope: DiffScope, *,
                 context_lines: int = DEFAULT_CONTEXT_LINES,
                 max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                 max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
                 max_graph_bytes: int | None = DEFAULT_MAX_GRAPH_BYTES,
                 include_graph: bool = True,
                 ) -> tuple[str, dict]:
    """Assemble the review bundle. Returns (text, stats).

    The stats are part of the contract: the check summary and the eval harness
    both read them, and both would rather show "3 files skipped, 1 truncated"
    than imply a completeness that did not happen. Graph fields (AIM-233) are
    always present so cost-delta reporting does not need key checks.
    """
    stats: dict = {
        "files_included": 0,
        "files_skipped": [],   # [{path, reason}]
        "truncated_files": [],
        "total_cap_hit": False,
        "bytes": 0,
        "bytes_without_graph": 0,
        "estimated_tokens": 0,
        "estimated_tokens_without_graph": 0,
        "graph_delta_bytes": 0,
        "graph_delta_tokens": 0,
        **_empty_graph_stats(),
    }
    sections: list[str] = []
    used = 0
    included_paths: list[tuple[str, list[tuple[int, int]]]] = []

    for path in scope.paths:
        reason = _skip_reason(path)
        if reason:
            stats["files_skipped"].append({"path": path, "reason": reason})
            continue
        text = _read_text(repo_dir, path)
        if text is None:
            stats["files_skipped"].append({"path": path, "reason": "binary or unreadable"})
            continue

        lines = text.splitlines()
        ranges = sorted(scope.added_lines[path])
        section = _section(path, lines, ranges, context_lines)
        if len(section.encode()) > max_file_bytes:
            # Shrink the context window first; the added lines themselves are
            # the reason the file is here and are cut last.
            stats["truncated_files"].append(path)
            section = _section(path, lines, ranges, min(5, context_lines))
            if len(section.encode()) > max_file_bytes:
                section = _section(path, lines, ranges, 0)
            if len(section.encode()) > max_file_bytes:
                section = section.encode()[:max_file_bytes].decode("utf-8", "replace")
                section += "\n... [file truncated at byte cap]"

        size = len(section.encode()) + 2  # blank line between sections
        if used + size > max_total_bytes:
            stats["total_cap_hit"] = True
            stats["files_skipped"].append({"path": path, "reason": "total byte cap"})
            continue
        sections.append(section)
        included_paths.append((path, ranges))
        used += size
        stats["files_included"] += 1

    preamble = ("# Pull-request security review bundle\n"
                "# Lines prefixed '+' were added by this PR; the rest is "
                "context. Report issues in '+' lines only.\n\n")
    preamble_size = len(preamble.encode()) if sections else 0
    # Diff-only bundle size (pre-graph) for the cost-delta line.
    diff_body = "\n\n".join(sections)
    if diff_body:
        diff_only = preamble + diff_body
    else:
        diff_only = ""
    stats["bytes_without_graph"] = len(diff_only.encode())
    stats["estimated_tokens_without_graph"] = stats["bytes_without_graph"] // 4

    # Repo-graph slice: spend only what remains under the total hard cap,
    # further limited by max_graph_bytes. Diff hunks always win.
    graph_text = ""
    if include_graph and sections:
        from . import graph as graph_mod  # local: keep context importable alone
        budget_remaining = max(0, max_total_bytes - len(diff_only.encode()))
        graph_cap = DEFAULT_MAX_GRAPH_BYTES if max_graph_bytes is None else max_graph_bytes
        graph_budget = min(budget_remaining, max(0, graph_cap))
        if graph_budget > 0:
            try:
                index = graph_mod.build_index(repo_dir)
                graph_text, gstats = graph_mod.format_graph_section(
                    index, included_paths, max_bytes=graph_budget,
                    repo_dir=repo_dir)
                for key, value in gstats.items():
                    stats[key] = value
            except Exception as exc:  # noqa: BLE001 — graph must never kill a review
                stats["graph_enabled"] = True
                stats["graph_skipped"] = [{"path": "*", "reason": f"graph build failed: {exc}"[:200]}]
                graph_text = ""

    if graph_text:
        bundle = diff_only + "\n\n" + graph_text
    else:
        bundle = diff_only

    # Absolute hard cap as a final belt (graph formatter already budgets, but
    # a race between len() and encoding should never breach the contract).
    if len(bundle.encode()) > max_total_bytes:
        bundle = bundle.encode()[:max_total_bytes].decode("utf-8", "replace")
        stats["total_cap_hit"] = True
        stats["graph_cap_hit"] = True

    stats["bytes"] = len(bundle.encode())
    stats["estimated_tokens"] = stats["bytes"] // 4
    stats["graph_delta_bytes"] = max(0, stats["bytes"] - stats["bytes_without_graph"])
    stats["graph_delta_tokens"] = max(
        0, stats["estimated_tokens"] - stats["estimated_tokens_without_graph"])
    # Prefer the precise graph_bytes when the section was built cleanly.
    if stats.get("graph_bytes") and stats["graph_delta_bytes"] == 0 and graph_text:
        stats["graph_delta_bytes"] = stats["graph_bytes"]
        stats["graph_delta_tokens"] = stats["graph_bytes"] // 4
    return bundle, stats
