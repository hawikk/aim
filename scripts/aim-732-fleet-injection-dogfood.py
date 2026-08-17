#!/usr/bin/env python3
"""AIM-732 metadata-safe fleet injection dogfood harness.

Runs FLT-01–05 (offline) and FLT-10–13 (synthetic dogfood) against the
unified matcher + guardrail engine. Measures detections without capturing
prompt/transcript text in the emitted event records.

Usage:
  python3 scripts/aim-732-fleet-injection-dogfood.py
  python3 scripts/aim-732-fleet-injection-dogfood.py --json-out docs/security/aim-732-fleet-injection-measurement.json

Exit 0 only when every scenario passes.
"""

from __future__ import annotations

import argparse
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "guardrail" / "src"))
sys.path.insert(0, str(ROOT / "collectors" / "matcher-ruleset"))

# Import after path setup — the test module is the source of truth for cases.
from services.guardrail.tests import test_fleet_injection_dogfood as suite  # noqa: E402


def run() -> dict:
    mapping = {
        "test_flt01_jailbreak_with_aws_lure_still_flags_secret": "FLT-01",
        "test_flt02_clean_jailbreak_no_secret_pii": "FLT-02",
        "test_flt03_unapproved_mcp_call": "FLT-03",
        "test_flt04_inventory_unapproved_configured_mcp": "FLT-04",
        "test_flt05_unapproved_first_class_tool": "FLT-05",
        "test_flt10_hook_secret_under_ignore_instructions": "FLT-10",
        "test_flt11_unapproved_mcp_metadata_only": "FLT-11",
        "test_flt12_social_paste_prod_key_canary": "FLT-12",
        "test_flt13_multiturn_jailbreak_then_canary": "FLT-13",
        "test_schema_rejects_prompt_field_on_ingest_contract": "PRIVACY-GATE",
    }

    loader = unittest.TestLoader()
    tests = loader.loadTestsFromModule(suite)

    def _flatten(s):
        for t in s:
            if isinstance(t, unittest.TestSuite):
                yield from _flatten(t)
            else:
                yield t

    # Snapshot method names *before* run — some unittest versions clear the suite.
    planned = []
    for t in _flatten(tests):
        name = getattr(t, "_testMethodName", None)
        if name:
            planned.append(name)

    result = unittest.TextTestRunner(verbosity=2, stream=sys.stderr).run(tests)
    failed_names = {
        getattr(ftest, "_testMethodName", str(ftest)): (ferr or "fail")
        for ftest, ferr in (result.failures + result.errors)
    }
    ran = []
    for name in planned:
        flt = mapping.get(name, name)
        if name in failed_names:
            ok = False
            detail = failed_names[name].strip().splitlines()[-1][:200]
        else:
            ok = True
            detail = "pass"
        ran.append({"id": flt, "method": name, "ok": ok, "detail": detail})

    measurement = {
        "issue": "AIM-732",
        "title": "Prompt-injection / social fleet tests (metadata-safe)",
        "ran_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "synthetic-dogfood-offline",
        "privacy": {
            "prompt_fields_on_events": False,
            "canary_material_on_findings": False,
            "schema_rejects_prompt": True,
            "notes": (
                "Local canary text is scanned in-process only; emitted events "
                "carry match_flags/tool metadata. additionalProperties:false "
                "rejects prompt attachment at the ingest contract."
            ),
        },
        "summary": {
            "tests_run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "passed": result.wasSuccessful(),
        },
        "scenarios": ran,
        "pass_counts": {
            "offline_flt_01_05": sum(
                1 for s in ran if str(s["id"]).startswith("FLT-0") and s["ok"]
            ),
            "dogfood_flt_10_13": sum(
                1 for s in ran if str(s["id"]).startswith("FLT-1") and s["ok"]
            ),
            "privacy_gates": sum(
                1 for s in ran if s["id"] == "PRIVACY-GATE" and s["ok"]
            ),
        },
    }
    return measurement, result.wasSuccessful()



def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--json-out",
        type=Path,
        default=ROOT / "docs" / "security" / "aim-732-fleet-injection-measurement.json",
        help="Write machine-readable measurement (counts/metadata only)",
    )
    args = ap.parse_args()
    measurement, ok = run()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(measurement, indent=2) + "\n")
    print(json.dumps(measurement["summary"], indent=2))
    print(f"wrote {args.json_out}")
    for s in measurement["scenarios"]:
        print(f"  {'PASS' if s['ok'] else 'FAIL'}  {s['id']}  {s['method']}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
