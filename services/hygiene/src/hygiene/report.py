"""The report. One markdown document per run, written to disk and printed.

Design rule, learned from every security report nobody reads: **the remediation
is the report.** A finding without exact next steps is a finding an engineer
scrolls past, so each entry ends with copy-pasteable commands, and rotation
always comes before the history purge.

Failures are rendered at the top, above the findings, and a check that did not
run is stated explicitly. A report that shows "0 critical" while the history
scan crashed is worse than no report.
"""

from __future__ import annotations

import datetime

from . import bus
from .models import Finding
from .orchestrator import Run

_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪",
         "informational": "·"}

_CHECK_TITLE = {
    "history": "Check 1 — secrets recoverable from git history",
    "worktree": "Check 2 — working-tree hygiene",
    "tokens": "Check 3 — token scope audit",
}

ALL_CHECKS = ("history", "worktree", "tokens")


def render(run: Run, *, now: datetime.datetime | None = None,
           retention_days: int = 30, scanned_at: str = "") -> str:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    counts = run.counts()
    lines: list[str] = [
        f"# Secrets & token hygiene — {run.repo}",
        "",
        f"Scanned {scanned_at or now.strftime('%Y-%m-%d %H:%M:%SZ')} · "
        f"{len(run.findings)} finding{'s' if len(run.findings) != 1 else ''} · "
        + " · ".join(f"{_ICON[s]} {counts[s]} {s}"
                     for s in ("critical", "high", "medium", "low", "informational")
                     if counts.get(s)),
        "",
    ]

    if run.errors:
        lines += [
            "## ⛔ This scan is incomplete",
            "",
            "The counts above do **not** cover the checks below. Treat this report as "
            "partial until they run clean — a secrets scan that fails quietly is the "
            "failure mode this pillar exists to prevent.",
            "",
        ]
        lines += [f"- **{_CHECK_TITLE.get(k, k)}** failed: `{v}`" for k, v in run.errors.items()]
        lines.append("")

    skipped = [c for c in ALL_CHECKS if c not in run.ran and c not in run.errors]
    if skipped:
        lines += ["> Not run this pass: "
                  + ", ".join(f"**{_CHECK_TITLE.get(c, c)}**" for c in skipped)
                  + ". Not run is not the same as clean.", ""]

    if not run.findings:
        lines += ["## No findings", "",
                  "All checks that ran found nothing. "
                  f"{len(run.ran)} of {len(ALL_CHECKS)} checks ran.", ""]

    for check in ALL_CHECKS:
        items = [f for f in run.by_severity() if f.check == check]
        if not items:
            continue
        lines += [f"## {_CHECK_TITLE[check]}", ""]
        for finding in items:
            lines += _entry(finding, now=now)

    lines += [
        "---",
        "",
        "### Handling of secret values",
        "",
        "No secret value is stored, displayed, or transmitted by this report. Each finding "
        "carries an issuer prefix with the last four characters (enough to identify *which* "
        "key to rotate in a vault, not enough to authenticate) and a keyed HMAC fingerprint "
        "that is not reversible outside this host. Raw values exist only inside the scanner "
        "process and are never written to disk.",
        "",
        f"Findings state is retained for {retention_days} days and purged on every run.",
        "",
    ]
    return "\n".join(lines)


def _entry(finding: Finding, *, now: datetime.datetime) -> list[str]:
    severity = bus.severity_for(finding)
    out = [f"### {_ICON[severity]} {severity.upper()} — {finding.title}", ""]

    facts = [f"**Where:** `{finding.location}`"]
    if finding.masked:
        facts.append(f"**Value:** `{finding.masked}`")
    if finding.author_date:
        facts.append(f"**Committed:** {finding.author_date}{_age(finding.author_date, now)}")
    facts.append(f"**Liveness:** {_liveness(finding)}")
    if finding.fingerprint:
        facts.append(f"**Fingerprint:** `{finding.fingerprint[:16]}`")
    out += [" · ".join(facts), "", finding.message, ""]
    if finding.remediation:
        out += ["<details><summary><b>Remediation</b></summary>", "",
                "```", finding.remediation, "```", "", "</details>", ""]
    return out


def _liveness(finding: Finding) -> str:
    """Say what we know, and say plainly when we do not know."""
    if finding.liveness == "live":
        return (f"**VERIFIED LIVE** — authenticates right now as "
                f"`{finding.liveness_detail or 'a valid identity'}`. Rotate before anything else.")
    if finding.liveness == "dead":
        return ("issuer reports this credential is no longer valid. The history purge is "
                "still owed; the urgency is not.")
    if finding.liveness == "not_checked":
        return "not checked (verification disabled for this run)."
    reason = finding.liveness_reason
    return ("**unknown** — could not verify"
            + (f" ({reason})" if reason else "")
            + ". Treat as live until proven otherwise.")


def _age(date: str, now: datetime.datetime) -> str:
    """How long this has been exposed. The number that makes people act."""
    try:
        when = datetime.datetime.fromisoformat(date.replace("Z", "+00:00"))
    except ValueError:
        return ""
    days = (now - when).days
    return f" ({days} days ago)" if days > 0 else ""
