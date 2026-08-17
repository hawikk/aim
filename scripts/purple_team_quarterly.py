#!/usr/bin/env python3
"""Scaffold or refresh a quarterly purple-team report.

Collects live matcher rates + research-queue summary and writes
docs/security/purple-team-reports/<quarter>.md unless --dry-run.

Usage:
  python3 scripts/purple_team_quarterly.py --quarter 2026-Q3
  python3 scripts/purple_team_quarterly.py --quarter 2026-Q4 --dry-run
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "docs" / "security" / "purple-team-reports"


def run_json_evasion() -> dict:
    tmp = ROOT / "evasion-report.quarterly.tmp.json"
    try:
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "matcher_evasion_report.py"),
                "--check",
                "--json-report",
                str(tmp),
            ],
            check=False,
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if tmp.is_file():
            return json.loads(tmp.read_text(encoding="utf-8"))
    finally:
        if tmp.is_file():
            tmp.unlink(missing_ok=True)
    return {}


def run_research_summary() -> str:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "adversarial_research_report.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return (proc.stdout or proc.stderr or "").strip()


def rates_table(report: dict) -> str:
    rows = []
    # matcher_evasion_report json shape may vary; handle common forms
    by_rs = report.get("rulesets") or report.get("by_ruleset") or {}
    if not by_rs and "rates" in report:
        by_rs = report["rates"]
    if isinstance(by_rs, dict) and by_rs:
        for name, r in by_rs.items():
            if not isinstance(r, dict):
                continue
            bas = r.get("baseline") or r.get("baseline_pass") or "?"
            eva = r.get("evasion") or r.get("evasion_caught") or "?"
            fp = r.get("fp_guards") or r.get("fp") or "?"
            rows.append(f"| {name} | {bas} | {eva} | {fp} |")
    if not rows:
        # fall back: tell author to paste from --check stdout
        return (
            "| Ruleset | Baseline | Evasion caught | FP guards |\n"
            "|---|---|---|---|\n"
            "| _(paste from `python3 scripts/matcher_evasion_report.py --check`)_ | | | |"
        )
    header = (
        "| Ruleset | Baseline | Evasion caught | FP guards |\n"
        "|---|---|---|---|\n"
    )
    return header + "\n".join(rows)


def render(quarter: str, evasion: dict, research_stdout: str) -> str:
    today = dt.date.today().isoformat()
    return f"""# Purple-team report — {quarter}

**Program:** continuous purple-team
**Type:** quarterly exercise
**Date:** {today}
**Author:** _(fill)_
**Runbook:** `docs/security/purple-team-runbook.md`

## Executive summary

_(3–5 bullets: what was attacked, what changed, residual risk)_

## Measured rates (CI corpus)

{rates_table(evasion)}

Overall floors: baseline 100 / evasion ≥90 / FP 100 — **PASS / FAIL** _(circle)_

## Research queue

```
{research_stdout or "(no research output)"}
```

Promotions this quarter:

- _(case id → CI path or findings pin)_

## Engine adversarial

- Suite result: **PASS / FAIL**
- New DEFENDED:
- New KNOWN GAP:
- Flipped pins:

## Fleet / social (metadata-safe)

| Scenario | Result |
|---|---|
| FLT-… | |

## App-LLM / gateway

| Scenario | Result |
|---|---|
| APP-… | executed / N/A (reason) |

## Maturity score

| Before | After | Delta |
|---|---|---|
| | | |

Update `docs/security/adversarial-maturity-score.md` history when finalizing.

## Residual risk

1.
2.

## Sign-off

| Role | Name | Date |
|---|---|---|
| Purple lead | | |
| Security (if behavior change) | | |
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quarter", required=True, help="e.g. 2026-Q3")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing report file",
    )
    args = ap.parse_args()

    print("collecting matcher rates…")
    evasion = run_json_evasion()
    print("collecting research queue…")
    research = run_research_summary()
    body = render(args.quarter, evasion, research)

    out = REPORTS / f"{args.quarter}.md"
    if args.dry_run:
        print(body)
        return 0

    REPORTS.mkdir(parents=True, exist_ok=True)
    if out.exists() and not args.force:
        print(f"refusing to overwrite {out} (pass --force)", file=sys.stderr)
        return 2
    out.write_text(body, encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
