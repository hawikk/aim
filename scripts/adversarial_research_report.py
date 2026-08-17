#!/usr/bin/env python3
"""Report on the continuous adversarial research queue (AIM-636 / AIM-730).

Unlike scripts/matcher_evasion_report.py, this does NOT gate CI. It measures
techniques under investigation in collectors/matcher-fixtures/adversarial-research/
so monthly intake can promote or pin cases deliberately.

Usage:
  python3 scripts/adversarial_research_report.py
  python3 scripts/adversarial_research_report.py --json-report /tmp/research.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESEARCH_DIR = ROOT / "collectors" / "matcher-fixtures" / "adversarial-research"

MODULES = {
    "claude-code": "collectors/claude-code/aim_collector/matchers.py",
    "cursor": "collectors/cursor/cursor_collector/matchers.py",
    "kilo-code": "collectors/kilo-code/kilo_collector/matchers.py",
    "kimi-code": "collectors/kimi-code/kimi_collector/matchers.py",
}


def load_module(ruleset: str, path: str):
    spec = importlib.util.spec_from_file_location(f"matchers_{ruleset}", ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def load_cases() -> list[dict]:
    cases: list[dict] = []
    if not RESEARCH_DIR.is_dir():
        return cases
    for path in sorted(RESEARCH_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for case in data.get("cases", []):
            case = dict(case)
            case["_source"] = path.name
            cases.append(case)
    return cases


def measure(case: dict, mods: dict[str, object]) -> dict:
    rulesets = case.get("rulesets") or list(MODULES)
    expect = case.get("expect", "no-flag")
    rule = case.get("rule")
    text = case.get("input", "")
    per: dict[str, dict] = {}
    for rs in rulesets:
        mod = mods[rs]
        flags = list(mod.scan_text(text))  # type: ignore[attr-defined]
        caught = rule in flags if rule else bool(flags)
        if expect == "flag":
            ok = caught
        elif expect == "no-flag":
            ok = not caught
        else:
            ok = True
        per[rs] = {"flags": flags, "caught": caught, "expect_ok": ok}
    # unanimous across rulesets
    all_ok = all(v["expect_ok"] for v in per.values())
    any_caught = any(v["caught"] for v in per.values())
    return {
        "id": case.get("id"),
        "rule": rule,
        "expect": expect,
        "status": case.get("status"),
        "source": case.get("_source"),
        "hypothesis": case.get("hypothesis"),
        "note": case.get("note"),
        "any_caught": any_caught,
        "expect_ok": all_ok,
        "per_ruleset": {k: {"flags": v["flags"], "caught": v["caught"]} for k, v in per.items()},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json-report", type=Path, default=None)
    args = ap.parse_args()

    cases = load_cases()
    if not cases:
        print("no research-queue cases found under", RESEARCH_DIR)
        return 0

    mods = {rs: load_module(rs, path) for rs, path in MODULES.items()}
    results = [measure(c, mods) for c in cases]

    miss = [r for r in results if not r["any_caught"]]
    catch = [r for r in results if r["any_caught"]]
    expect_fail = [r for r in results if not r["expect_ok"]]

    print(f"research queue: {len(results)} cases from {RESEARCH_DIR.relative_to(ROOT)}")
    print(f"  measured catch: {len(catch)}  measured miss: {len(miss)}")
    if expect_fail:
        print(f"  WARNING: {len(expect_fail)} case(s) disagree with declared expect:")
        for r in expect_fail:
            print(f"    - {r['id']}: expect={r['expect']} any_caught={r['any_caught']}")
    else:
        print("  all cases match declared expect")

    print("\nby case:")
    for r in results:
        tag = "CATCH" if r["any_caught"] else "MISS "
        print(f"  {tag}  {r['id']:40} expect={r['expect']:8} status={r.get('status')}")

    if args.json_report:
        args.json_report.write_text(
            json.dumps(
                {
                    "total": len(results),
                    "caught": len(catch),
                    "missed": len(miss),
                    "expect_mismatches": len(expect_fail),
                    "cases": results,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {args.json_report}")

    # Research report is advisory: exit 0 even on expect mismatches so CI
    # does not take a dependency. Non-zero only if --strict passed later.
    return 0


if __name__ == "__main__":
    sys.exit(main())
