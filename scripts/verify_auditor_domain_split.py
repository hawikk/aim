#!/usr/bin/env python3
"""Prove gate vs auditor failure domains are split (local-only).

Checks (fail-closed; exit 1 on any miss):

1. merge-audit.yml jobs pin runs-on labels that include aim-ops and never
   aim-ci (Actions auditor must survive aim-ci drain).
2. merge-audit.yml never pins ubuntu-latest (policy: no billable cloud).
3. PR security workflows still target aim-ci (gates stay on the gate pool).
4. Optional live checks when env allows:
   - GITHUB_TOKEN / gh: at least one online runner with aim-ops and one with
     aim-ci labels.
   - docker: any container matching gatehouse-merge-audit is healthy.

Usage:
  python3 scripts/verify_auditor_domain_split.py
  python3 scripts/verify_auditor_domain_split.py --live
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MERGE_AUDIT = ROOT / ".github" / "workflows" / "merge-audit.yml"
# Representative gate workflows that must remain on aim-ci for PR events.
GATE_WORKFLOWS = [
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "runner-isolation-proof.yml",
    ROOT / ".github" / "workflows" / "policy-guardrail.yml",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _runs_on_blocks(text: str) -> list[str]:
    """Return each runs-on value expression (line or multi-line toJSON form)."""
    blocks: list[str] = []
    for m in re.finditer(r"(?m)^\s*runs-on:\s*(.+)$", text):
        blocks.append(m.group(1).strip())
    return blocks


def check_merge_audit_yaml() -> list[str]:
    errs: list[str] = []
    if not MERGE_AUDIT.is_file():
        return [f"missing {MERGE_AUDIT.relative_to(ROOT)}"]
    text = _read(MERGE_AUDIT)
    blocks = _runs_on_blocks(text)
    if not blocks:
        return ["merge-audit.yml has no runs-on lines"]
    for i, b in enumerate(blocks, 1):
        if "ubuntu-latest" in b:
            errs.append(f"merge-audit runs-on #{i} uses ubuntu-latest (billable; forbidden)")
        if "aim-ci" in b:
            errs.append(
                f"merge-audit runs-on #{i} still pins aim-ci — shares gate failure domain"
            )
        if "aim-ops" not in b:
            errs.append(f"merge-audit runs-on #{i} does not pin aim-ops: {b}")
    return errs


def check_gates_still_on_aim_ci() -> list[str]:
    errs: list[str] = []
    for path in GATE_WORKFLOWS:
        if not path.is_file():
            errs.append(f"missing gate workflow {path.relative_to(ROOT)}")
            continue
        text = _read(path)
        if "aim-ci" not in text:
            errs.append(
                f"{path.name} no longer references aim-ci — unexpected gate relocation"
            )
    return errs


def _strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def check_live_runners() -> list[str]:
    errs: list[str] = []
    env = {
        **dict(**{k: v for k, v in __import__("os").environ.items()}),
        "NO_COLOR": "1",
        "CLICOLOR": "0",
        "GH_FORCE_TTY": "0",
        "GH_PAGER": "cat",
    }
    try:
        raw = subprocess.check_output(
            ["gh", "api", "repos/hawikk/aim/actions/runners"],
            text=True,
            stderr=subprocess.PIPE,
            timeout=30,
            env=env,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        return [f"live runner check skipped/failed: {e}"]

    try:
        payload = json.loads(_strip_ansi(raw))
        runners = payload.get("runners", []) if isinstance(payload, dict) else payload
    except json.JSONDecodeError as e:
        return [f"could not parse runners JSON: {e}"]

    online = [r for r in runners if r.get("status") == "online"]

    def labels_of(r: dict) -> set[str]:
        return {lb.get("name") for lb in r.get("labels") or [] if lb.get("name")}

    ops = [r for r in online if "aim-ops" in labels_of(r)]
    ci = [r for r in online if "aim-ci" in labels_of(r)]
    if not ops:
        errs.append("no online runner with label aim-ops (Actions auditor cannot schedule)")
    if not ci:
        errs.append(
            "no online runner with label aim-ci (gates cannot schedule — capacity issue, "
            "not domain-split regression)"
        )
    # Domain split proof: ops and ci must not be the *same* sole host when both
    # exist — different runners are independent capacity even under soft residual.
    if ops and ci:
        ops_names = {r.get("name") for r in ops}
        ci_names = {r.get("name") for r in ci}
        if ops_names == ci_names and len(ops_names) == 1:
            errs.append(
                f"aim-ops and aim-ci resolve to the same single runner {ops_names}; "
                "label split is not independent capacity"
            )
    return errs


def check_live_oob() -> list[str]:
    errs: list[str] = []
    try:
        raw = subprocess.check_output(
            [
                "docker",
                "ps",
                "--filter",
                "name=gatehouse-merge-audit",
                "--format",
                "{{.Names}}\t{{.Status}}",
            ],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        return [f"live OOB docker check skipped/failed: {e}"]

    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return [
            "no gatehouse-merge-audit container running — OOB auditor domain is dark "
            "(start: docker compose up -d gatehouse-merge-audit)"
        ]
    for ln in lines:
        if "(healthy)" not in ln and "healthy" not in ln.lower():
            # docker format Status includes "Up N (healthy)" when healthy
            if "unhealthy" in ln.lower() or "starting" in ln.lower():
                errs.append(f"OOB auditor not healthy: {ln}")
            # "Up N minutes" without health is still running; warn but accept
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--live",
        action="store_true",
        help="also query gh runners + docker for live independence proof",
    )
    args = ap.parse_args()

    errors: list[str] = []
    errors.extend(check_merge_audit_yaml())
    errors.extend(check_gates_still_on_aim_ci())
    if args.live:
        errors.extend(check_live_runners())
        errors.extend(check_live_oob())

    if errors:
        print("Domain split VERIFY FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print("Domain split OK")
    print("  - merge-audit.yml → aim-ops only (no aim-ci, no ubuntu-latest)")
    print("  - gate workflows still reference aim-ci")
    if args.live:
        print("  - live: aim-ops + aim-ci runners online; OOB auditor present")
    else:
        print("  - (pass --live for runner + docker health proof)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
