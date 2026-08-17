"""Rendering: one check run, one comment, and never a second one.

Pure functions — no network — so the exact bytes GitHub receives are asserted in
unit tests rather than inspected by eye on a live PR.

Two product rules are enforced here:

* **One comment per PR, edited in place.** The marker `<!-- gatehouse:v1 -->`
  is how the poster finds its previous comment. A bot that posts a fresh
  comment per push is the reason engineers mute security bots, and "no comment
  spam" is an acceptance criterion, not a nicety.
* **Everything interpolated is untrusted.** Rule ids, file paths and resource
  names come out of the PR's own tree. `md()` neutralizes them before they land
  in Markdown that a reviewer — or, one pillar over, a triage model — will
  read. This is the alert contract's §7.9 applied at the other end of the wire.

The failing threshold is configuration, not code: Security owns "what blocks a
merge", gatehouse owns "what is true".
"""

from __future__ import annotations

import os

from .models import Finding

MARKER = "<!-- gatehouse:v1 -->"
# Marker on inline review comments so a re-push can identify gatehouse threads
# on the Files changed tab.
INLINE_MARKER = "<!-- gatehouse:inline:v1 -->"
MAX_ANNOTATIONS_PER_REQUEST = 50  # GitHub's cap; the rest go in follow-up updates
MAX_LISTED_IN_COMMENT = 20
# Cap inline review comments so a noisy pack cannot flood Files changed.
# Remaining findings still appear as check-run annotations + the summary table.
MAX_INLINE_REVIEW_COMMENTS = int(os.environ.get("GATEHOUSE_MAX_INLINE_COMMENTS", "30"))

# Default proposal, overridable per install: critical/high block, everything
# else is reported without failing the check. Not a decision this service gets
# to make on its own — see module docstring.
FAIL_ON = os.environ.get("GATEHOUSE_FAIL_ON", "high")
_BLOCKING_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_LEVEL = {"critical": "failure", "high": "failure", "medium": "warning",
          "low": "notice", "informational": "notice"}
_ICON = {"critical": "🛑", "high": "🔴", "medium": "🟠", "low": "🟡",
         "informational": "⚪"}


def md(text: str, limit: int = 160) -> str:
    """Make untrusted text safe to interpolate into Markdown.

    Backticks and pipes break out of code spans and table cells; angle brackets
    open raw HTML, which GitHub renders in comments. Newlines collapse so one
    crafted path cannot restructure the summary. The same defensive rendering
    the alert contract requires of bus consumers (§7.9), applied here because
    this text reaches a human reviewer first.
    """
    cleaned = (text or "").replace("`", "'").replace("|", "/").replace("<", "&lt;")
    cleaned = cleaned.replace(">", "&gt;").replace("\r", " ").replace("\n", " ")
    return " ".join(cleaned.split())[:limit]


def is_merge_blocking(finding: Finding) -> bool:
    """Whether a finding is *allowed* to fail the check.

    Unreachable SCA findings are still reported and published to the bus, but
    they never block a merge — the precision bar for dependency scanning.
    `unknown` and `reachable` still honour the severity threshold; only a
    positive "no first-party import" verdict gets the free pass.
    """
    if finding.finding_type == "pr_security.vulnerable_dependency":
        if (finding.labels or {}).get("reachability") == "unreachable":
            return False
    return True


def blocks(findings: list[Finding], fail_on: str = FAIL_ON,
           include_ai: bool = False,
           observe: set[str] | None = None) -> list[Finding]:
    """Findings at or above the blocking threshold.

    AI-review findings are excluded unless the repo opted in (`ai_blocking`):
    the model's output is advisory by default, so it must not be able to fail
    a check on its own.

    Unreachable SCA findings are excluded even when severity is critical
    (guardrail-precision lens).

    Scanners in observe mode (precision budget breach) are also
    excluded: their findings still appear on the check and the bus, but they
    cannot fail a merge until precision is restored.
    """
    from . import modes as gate_modes

    threshold = _BLOCKING_RANK.get(fail_on, 1)
    silent = observe if observe is not None else gate_modes.observe_scanners()
    return [f for f in findings
            if _BLOCKING_RANK[f.severity] <= threshold
            and (include_ai or f.scanner != "ai-review")
            and is_merge_blocking(f)
            and f.scanner not in silent]


def conclusion(findings: list[Finding], *, errors: list[str],
               fail_on: str = FAIL_ON, fail_ai: bool = False,
               observe: set[str] | None = None) -> str:
    """`failure`, `neutral` or `success`.

    A scanner error can never produce `success`. "We could not look" and "we
    looked and it was clean" are different statements, and collapsing them into
    a green check is how a security gate lies.
    """
    if blocks(findings, fail_on, include_ai=fail_ai, observe=observe):
        return "failure"
    if errors:
        return "neutral"
    return "neutral" if findings else "success"


def counts(findings: list[Finding]) -> dict[str, int]:
    tally: dict[str, int] = {}
    for finding in findings:
        tally[finding.severity] = tally.get(finding.severity, 0) + 1
    return tally


def title(findings: list[Finding], errors: list[str]) -> str:
    if not findings and not errors:
        return "No new security findings"
    tally = counts(findings)
    parts = [f"{tally[s]} {s}" for s in
             ("critical", "high", "medium", "low", "informational") if s in tally]
    head = ", ".join(parts) or "no findings"
    return f"{head}{' — scan incomplete' if errors else ''}"[:255]


def annotations(findings: list[Finding]) -> list[dict]:
    """One annotation per finding, anchored to the line the PR introduced."""
    out = []
    for finding in findings:
        line = finding.line or 1
        message = md(finding.message or finding.title, 480)
        if finding.remediation:
            message += f"\n\nFix: {md(finding.remediation, 300)}"
        out.append({
            "path": finding.path,
            "start_line": line,
            "end_line": max(line, finding.end_line or line),
            "annotation_level": _LEVEL[finding.severity],
            "title": f"[{finding.severity}] {md(finding.rule_id, 60)}"[:255],
            "message": message[:64000],
            "raw_details": f"scanner: {finding.scanner}\nrule: {md(finding.rule_id, 80)}",
        })
    return out


def _inline_body(finding: Finding) -> str:
    """Markdown for one PR review comment on the exact diff line.

    Leaders annotate the line; status-check-only noise is what we are replacing.
    Fix hint is always present when the rule pack provides remediation (every
    vendored SAST rule does).
    """
    bits = [
        INLINE_MARKER,
        f"**[{finding.severity}]** `{md(finding.rule_id, 80)}` "
        f"({md(finding.scanner, 40)})",
        "",
        md(finding.message or finding.title, 600),
    ]
    if finding.remediation:
        bits.extend(["", f"**Fix:** {md(finding.remediation, 400)}"])
    cwe = (finding.labels or {}).get("cwe")
    if cwe:
        bits.append(f"\n<sub>{md(cwe, 80)}</sub>")
    return "\n".join(bits)[:65536]


def inline_review_comments(
    findings: list[Finding],
    *,
    max_comments: int = MAX_INLINE_REVIEW_COMMENTS,
    scanners: frozenset[str] | None = None,
    skip_paths_lines: set[tuple[str, int]] | None = None,
) -> list[dict]:
    """GitHub pull-request review comments for line-anchored findings.

    Only findings with a real path and line are included — file-level findings
    (e.g. many SCA hits) stay on the check run. Diff-scoping happens earlier in
    the orchestrator; this function will not invent lines.

    Returns the `comments` array for `POST .../pulls/{n}/reviews` (event COMMENT).
    """
    skip = skip_paths_lines or set()
    ranked = sorted(
        findings,
        key=lambda f: (_BLOCKING_RANK.get(f.severity, 9), f.path or "", f.line or 0),
    )
    out: list[dict] = []
    for finding in ranked:
        if scanners is not None and finding.scanner not in scanners:
            continue
        if not finding.path or not finding.line:
            continue
        key = (finding.path, int(finding.line))
        if key in skip:
            continue
        out.append({
            "path": finding.path,
            "line": int(finding.line),
            "side": "RIGHT",
            "body": _inline_body(finding),
        })
        skip.add(key)
        if len(out) >= max_comments:
            break
    return out


def batches(items: list[dict], size: int = MAX_ANNOTATIONS_PER_REQUEST):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def summary(findings: list[Finding], *, suppressed: list[tuple[Finding, str]],
            errors: list[str], config_problems: list[str], scanned_files: int,
            cached_files: int, duration_ms: int, fail_on: str = FAIL_ON,
            ai_stats: dict | None = None, ai_blocking: bool = False,
            suggestions_md: str = "") -> str:
    """The check-run summary. Also the body of the single PR comment."""
    ai_findings = [f for f in findings if f.scanner == "ai-review"]
    scanner_findings = [f for f in findings if f.scanner != "ai-review"]
    lines: list[str] = []
    if scanner_findings:
        lines.append(f"**{len(scanner_findings)} finding(s)** in the lines this pull request changed.\n")
        # Reachability column only when SCA findings are present so
        # the default secrets/SAST/IaC table stays compact.
        has_sca = any(f.finding_type == "pr_security.vulnerable_dependency"
                      for f in scanner_findings)
        if has_sca:
            lines.append("| | Severity | Rule | Location | Scanner | Reachability |")
            lines.append("|---|---|---|---|---|---|")
        else:
            lines.append("| | Severity | Rule | Location | Scanner |")
            lines.append("|---|---|---|---|---|")
        for finding in scanner_findings[:MAX_LISTED_IN_COMMENT]:
            location = (f"{md(finding.path, 80)}:{finding.line}" if finding.line
                        else md(finding.path, 80))
            row = (
                f"| {_ICON[finding.severity]} | {finding.severity} | "
                f"{md(finding.rule_id, 60)} | {location} | {finding.scanner} |"
            )
            if has_sca:
                reach = (finding.labels or {}).get("reachability") or "—"
                row += f" {md(reach, 16)} |"
            lines.append(row)
        if len(scanner_findings) > MAX_LISTED_IN_COMMENT:
            lines.append(f"\n…and {len(scanner_findings) - MAX_LISTED_IN_COMMENT} more — every "
                         "finding is annotated inline on the **Files changed** tab.")
        sca_unreach = [
            f for f in scanner_findings
            if f.finding_type == "pr_security.vulnerable_dependency"
            and (f.labels or {}).get("reachability") == "unreachable"
        ]
        if sca_unreach:
            lines.append(
                f"\n**{len(sca_unreach)} unreachable SCA finding(s)** are reported "
                "and published to the alert bus but **do not fail this check** "
                "(import-level reachability)."
            )
        blocking = blocks(scanner_findings, fail_on)
        if blocking:
            lines.append(f"\n**{len(blocking)} of these fail this check** "
                         f"(threshold: {fail_on} and above).")
        # code-to-cloud — would-be CNAPP cloud findings on this PR.
        from . import cnapp_parity
        would_be = cnapp_parity.render_would_be_section(scanner_findings)
        if would_be:
            lines.append(would_be)
        from . import modes as gate_modes
        observing = sorted(gate_modes.observe_scanners())
        if observing:
            lines.append(
                f"\n> [!NOTE]\n> **Observe mode**: "
                f"`{'`, `'.join(observing)}` findings are reported but do not "
                "fail this check — precision budget breach; re-enforce when "
                "the gate corpus is green.")
    elif not ai_findings:
        lines.append("No new security findings in the changed lines. ✅")

    if suggestions_md:
        lines.append(suggestions_md)

    if ai_findings:
        # Advisory by design: the model reviewed the same diff the scanners
        # did, but its output is untrusted and opt-in to block on.
        mode = ("blocking per repo config" if ai_blocking
                else "advisory — does not fail this check")
        lines.append(f"\n**AI security review** ({mode})\n")
        for finding in ai_findings[:MAX_LISTED_IN_COMMENT]:
            location = (f"{md(finding.path, 80)}:{finding.line}" if finding.line
                        else md(finding.path, 80))
            category = finding.rule_id.removeprefix("ai/")
            lines.append(f"- 🤖 **{finding.severity}** `{md(category, 30)}` — "
                         f"{md(finding.title, 140)} ({location})")
        if len(ai_findings) > MAX_LISTED_IN_COMMENT:
            lines.append(f"- …and {len(ai_findings) - MAX_LISTED_IN_COMMENT} more.")
        if ai_stats:
            cost_bits = (
                f"est. cost ${ai_stats.get('estimated_cost_usd', 0.0):.4f}")
            graph_bytes = int(ai_stats.get("graph_delta_bytes")
                              or ai_stats.get("graph_bytes") or 0)
            graph_delta_cost = float(ai_stats.get("graph_delta_cost_usd") or 0.0)
            if graph_bytes:
                cost_bits += (
                    f" (repo-graph +{graph_bytes} B"
                    f" / +${graph_delta_cost:.4f}"
                    f", {int(ai_stats.get('graph_symbols') or 0)} symbols)")
            lines.append(
                f"<sub>{ai_stats.get('tokens_in', 0)} tokens in, "
                f"{ai_stats.get('tokens_out', 0)} out"
                f"{' (estimated)' if ai_stats.get('tokens_estimated') else ''}, "
                f"{cost_bits} — "
                "diff hunks plus capped context"
                f"{' and call-graph signatures' if graph_bytes else ''} "
                "left the runner; no code is stored.</sub>")

    if suppressed:
        lines.append(f"\n<details><summary>{len(suppressed)} finding(s) suppressed by "
                     "<code>.gatehouse.yml</code></summary>\n")
        for finding, reason in suppressed[:MAX_LISTED_IN_COMMENT]:
            lines.append(f"- `{md(finding.rule_id, 60)}` at {md(finding.path, 80)} — "
                         f"{md(reason, 200)}")
        lines.append("\nSuppressed findings do not fail this check. They are still "
                     "published to the security alert bus.\n</details>")

    if errors:
        lines.append("\n> [!WARNING]\n> **This scan is incomplete.** "
                     + "; ".join(md(e, 200) for e in errors[:3])
                     + "\n> A green check would have meant \"clean\"; this one can only "
                       "mean \"what ran, passed\".")
    if config_problems:
        lines.append("\n> [!NOTE]\n> `.gatehouse.yml`: "
                     + "; ".join(md(p, 200) for p in config_problems[:5]))

    lines.append(f"\n<sub>{scanned_files} changed file(s) scanned, {cached_files} reused from "
                 f"the previous push, {duration_ms / 1000:.1f}s. Repo contents were scanned in "
                 "an ephemeral workspace and deleted — findings are retained, code is not.</sub>")
    return "\n".join(lines)[:65000]


def comment_body(body: str) -> str:
    """The single PR comment. Marker first, so the next push finds and edits it."""
    return f"{MARKER}\n### 🛡️ gatehouse security review\n\n{body}"


def should_comment(findings: list[Finding], errors: list[str]) -> bool:
    """Comment only when there is something to say.

    A clean PR gets a green check and silence. The one exception lives in
    `github.upsert_comment`: if a previous comment exists it is *edited* to the
    all-clear, so the last thing an engineer read is not a stale list of
    findings they have since fixed.
    """
    return bool(findings or errors)
