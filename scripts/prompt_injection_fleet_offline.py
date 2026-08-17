#!/usr/bin/env python3
"""AIM-732 offline prompt-injection / social fleet pack runner.

Executes synthetic FLT scenarios against:
  1. Unified endpoint matchers (collectors/matcher-ruleset)
  2. Guardrail engine (policies/guardrail/v1)
  3. Canonical event schema (packages/schema) — metadata-only gate

Attack text stays in-process. Events and findings are asserted free of prompt
bodies. Exit 0 when every scenario passes; --json-report writes a purple-team
evidence artifact (counts + rule_ids only).

Usage:
  python3 scripts/prompt_injection_fleet_offline.py
  python3 scripts/prompt_injection_fleet_offline.py --check
  python3 scripts/prompt_injection_fleet_offline.py --json-report /tmp/flt-report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "collectors" / "matcher-fixtures" / "fleet" / "prompt-injection-social.json"
MATCHER_DIR = ROOT / "collectors" / "matcher-ruleset"
GUARDRAIL_SRC = ROOT / "services" / "guardrail" / "src"
RULES_DIR = ROOT / "policies" / "guardrail" / "v1"
SCHEMA_PATH = ROOT / "packages" / "schema" / "schema" / "v1" / "ai-usage-event.schema.json"

# Forbidden content keys that must never ride on emitted events/findings.
_CONTENT_KEYS = frozenset({
    "prompt", "response", "content", "message", "messages", "transcript",
    "input", "output", "arguments", "args", "body", "text", "raw_prompt",
})


def _import_stack():
    sys.path.insert(0, str(MATCHER_DIR))
    sys.path.insert(0, str(GUARDRAIL_SRC))
    import matchers  # type: ignore  # noqa: WPS433
    from guardrail.engine import Engine  # type: ignore  # noqa: WPS433
    from guardrail.rules import load_ruleset  # type: ignore  # noqa: WPS433
    from jsonschema import Draft202012Validator  # type: ignore  # noqa: WPS433

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    engine = Engine(load_ruleset(RULES_DIR))
    return matchers, engine, validator


def base_event(**over: Any) -> dict:
    event = {
        "schema_version": "1.0",
        "event_id": "11111111-1111-4111-8111-0000000000a1",
        "ts": "2026-08-01T12:00:00Z",
        "host_ref": "a" * 64,
        "user_ref": "b" * 64,
        "tool": "claude_code",
        "tool_version": "1.0.62",
        "provider": "anthropic",
        "model": "claude-sonnet-4-5",
        "session_id": "flt-sess-offline",
        "tokens_in": 100,
        "tokens_out": 50,
        "repo_ref": "c" * 64,
        "match_flags": [],
        "source": "endpoint",
    }
    event.update(over)
    return event


def flags_to_match_flags(detectors: list[str]) -> list[dict]:
    """Name-only match_flags (enforcement/test path). No matched content."""
    out = []
    for name in sorted(set(detectors)):
        category = name.split(":", 1)[0] if ":" in name else "policy"
        if category not in ("secret", "pii", "injection", "policy"):
            category = "policy"
        severity = {
            "secret": "high",
            "pii": "medium",
            "injection": "medium",
            "policy": "low",
        }[category]
        out.append({
            "detector": name[:64],
            "category": category,
            "severity": severity,
        })
    return out


def assert_no_content_leak(obj: Any, forbidden_substrings: list[str]) -> list[str]:
    """Return list of privacy violations found in a JSON-serializable object."""
    violations: list[str] = []
    dumped = json.dumps(obj, default=str)

    def walk(node: Any, path: str = "$") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k in _CONTENT_KEYS:
                    violations.append(f"forbidden key {path}.{k}")
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(obj)
    for s in forbidden_substrings:
        if s and s in dumped:
            # Allow short canary fragments only if they appear inside detector
            # names (they never should). Treat any full canary as a leak.
            violations.append(f"canary/prompt fragment leaked into payload: {s[:24]}…")
    return violations


def _expect_any(got: set[str], expected_any: list[str] | None) -> str | None:
    if not expected_any:
        return None
    if got.intersection(expected_any):
        return None
    return f"expected any of {expected_any}, got {sorted(got)}"


def _forbid_prefixes(got: set[str], prefixes: list[str] | None) -> str | None:
    if not prefixes:
        return None
    bad = [d for d in got if any(d.startswith(p) for p in prefixes)]
    if bad:
        return f"forbidden detectors present: {bad}"
    return None


def _expect_rules(got: set[str], expected: list[str] | None) -> str | None:
    if not expected:
        return None
    missing = [r for r in expected if r not in got]
    if missing:
        return f"missing engine rules {missing}; got {sorted(got)}"
    return None


def _forbid_rules(got: set[str], forbidden: list[str] | None) -> str | None:
    if not forbidden:
        return None
    hit = [r for r in forbidden if r in got]
    if hit:
        return f"forbidden engine rules fired: {hit}"
    return None


def run_matcher_engine(
    scenario: dict,
    matchers,
    engine,
    validator,
    input_text: str | None = None,
) -> dict:
    text = input_text if input_text is not None else scenario.get("input", "")
    detectors = matchers.scan_text(text)
    det_set = set(detectors)
    errors: list[str] = []

    err = _expect_any(det_set, scenario.get("expect_detectors_any"))
    if err:
        errors.append(err)
    err = _forbid_prefixes(det_set, scenario.get("forbid_detectors_prefixes"))
    if err:
        errors.append(err)

    event = base_event(match_flags=flags_to_match_flags(detectors))
    # Schema gate: event must validate; prompt text must not be present.
    schema_errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
    if schema_errors:
        errors.append(f"schema invalid: {schema_errors[0].message}")

    leaks = assert_no_content_leak(event, [text] if text else [])
    if leaks:
        errors.extend(leaks)

    findings, _audit = engine.evaluate(event)
    rule_ids = {f["rule_id"] for f in findings}
    err = _expect_rules(rule_ids, scenario.get("expect_engine_rules"))
    if err:
        errors.append(err)
    err = _forbid_rules(rule_ids, scenario.get("forbid_engine_rules"))
    if err:
        errors.append(err)

    leaks = assert_no_content_leak(findings, [text] if text else [])
    if leaks:
        errors.extend(leaks)

    return {
        "id": scenario["id"],
        "title": scenario.get("title"),
        "tier": scenario.get("tier"),
        "kind": "matcher_engine",
        "detectors": sorted(det_set),
        "engine_rules": sorted(rule_ids),
        "pass": not errors,
        "errors": errors,
    }


def run_engine_event(scenario: dict, engine, validator) -> dict:
    overlay = deepcopy(scenario.get("event_overlay") or {})
    event = base_event(**overlay)
    for field in scenario.get("drop_fields") or []:
        event.pop(field, None)

    errors: list[str] = []
    schema_errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
    if schema_errors:
        # Inventory / tool_use may use newer schema_version; retry with 1.2
        # if configured_mcp_servers present, else record the error.
        if "configured_mcp_servers" in event or event.get("event_type") in (
            "tool_use", "inventory",
        ):
            event = dict(event)
            event["schema_version"] = "1.2"
            schema_errors = sorted(
                validator.iter_errors(event), key=lambda e: list(e.path)
            )
        if schema_errors:
            errors.append(f"schema invalid: {schema_errors[0].message}")

    leaks = assert_no_content_leak(event, [])
    if leaks:
        errors.extend(leaks)
    # Tool calls must never carry argument-like keys.
    for i, tc in enumerate(event.get("tool_calls") or []):
        extra = set(tc) - {"tool_name", "mcp_server", "action_class", "count", "duration_ms"}
        if extra:
            errors.append(f"tool_calls[{i}] has non-metadata keys: {sorted(extra)}")

    findings, _ = engine.evaluate(event)
    rule_ids = {f["rule_id"] for f in findings}
    err = _expect_rules(rule_ids, scenario.get("expect_engine_rules"))
    if err:
        errors.append(err)
    err = _forbid_rules(rule_ids, scenario.get("forbid_engine_rules"))
    if err:
        errors.append(err)
    leaks = assert_no_content_leak(findings, [])
    if leaks:
        errors.extend(leaks)

    return {
        "id": scenario["id"],
        "title": scenario.get("title"),
        "tier": scenario.get("tier"),
        "kind": "engine_event",
        "detectors": [],
        "engine_rules": sorted(rule_ids),
        "pass": not errors,
        "errors": errors,
    }


def run_multi_turn(scenario: dict, matchers, engine, validator) -> dict:
    errors: list[str] = []
    turn_results = []
    for i, turn in enumerate(scenario.get("turns") or []):
        sub = {
            "id": f"{scenario['id']}.t{i}",
            "title": turn.get("role", "user"),
            "tier": scenario.get("tier"),
            "input": turn["input"],
            "expect_detectors_any": turn.get("expect_detectors_any"),
            "forbid_detectors_prefixes": turn.get("forbid_detectors_prefixes"),
            "expect_engine_rules": turn.get("expect_engine_rules"),
            "forbid_engine_rules": turn.get("forbid_engine_rules"),
        }
        r = run_matcher_engine(sub, matchers, engine, validator, input_text=turn["input"])
        turn_results.append(r)
        if not r["pass"]:
            errors.extend([f"turn{i}: {e}" for e in r["errors"]])

    return {
        "id": scenario["id"],
        "title": scenario.get("title"),
        "tier": scenario.get("tier"),
        "kind": "multi_turn_matcher_engine",
        "detectors": sorted({d for t in turn_results for d in t["detectors"]}),
        "engine_rules": sorted({r for t in turn_results for r in t["engine_rules"]}),
        "turns": turn_results,
        "pass": not errors,
        "errors": errors,
    }


def run_all() -> dict:
    pack = json.loads(FIXTURE.read_text(encoding="utf-8"))
    matchers, engine, validator = _import_stack()
    results = []
    for scenario in pack["scenarios"]:
        kind = scenario.get("kind")
        if kind == "matcher_engine":
            results.append(run_matcher_engine(scenario, matchers, engine, validator))
        elif kind == "engine_event":
            results.append(run_engine_event(scenario, engine, validator))
        elif kind == "multi_turn_matcher_engine":
            results.append(run_multi_turn(scenario, matchers, engine, validator))
        else:
            results.append({
                "id": scenario.get("id", "?"),
                "pass": False,
                "errors": [f"unknown kind {kind!r}"],
                "detectors": [],
                "engine_rules": [],
            })

    passed = sum(1 for r in results if r["pass"])
    failed = [r["id"] for r in results if not r["pass"]]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "issue": "AIM-732",
        "fixture": str(FIXTURE.relative_to(ROOT)),
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "privacy": {
            "prompt_bodies_on_events": False,
            "prompt_bodies_on_findings": False,
            "measurement": "match_flags detector names + engine rule_ids only",
        },
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit non-zero on any failure (CI)")
    parser.add_argument("--json-report", type=Path, help="write machine-readable evidence")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    report = run_all()
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if not args.quiet:
        status = "PASS" if not report["failed"] else "FAIL"
        print(f"AIM-732 fleet pack: {status} ({report['passed']}/{report['total']})")
        for r in report["results"]:
            mark = "ok" if r["pass"] else "FAIL"
            rules = ",".join(r.get("engine_rules") or []) or "-"
            dets = ",".join(r.get("detectors") or []) or "-"
            print(f"  [{mark}] {r['id']}: detectors={dets} rules={rules}")
            for e in r.get("errors") or []:
                print(f"         - {e}")
        print(f"privacy: {report['privacy']['measurement']}")

    # Always non-zero on failure (CI and local). --check is accepted for
    # symmetry with matcher_evasion_report.py but is not required.
    return 0 if not report["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
