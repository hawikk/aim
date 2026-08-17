#!/usr/bin/env python3
"""AIM-1149 — secret-enforce posture fixtures + dark-gate assertion.

The AIM-611 / AIM-563 quiet gate went dark when live pilot telemetry showed
**0 hosts** with enforce-hash posture (policy=absent). Calendar remeasure is
operator-owned; this script hardens the *measurement path* so CI fails if the
fixture set (or its aggregation) can regress to the dark shape without a red X.

What "enforce-hash posture" means (matches AIM-561 / AIM-789 gate queries):
  enforcement_posture.policy = 'loaded'
  AND mode = 'enforce'
  AND policy_hash is a non-empty string

Dark shape (must fail closed):
  hosts_enforce_hash == 0  (equivalently: only absent / shadow / missing posture)

Usage:
  python3 scripts/check_secret_enforce_posture_fixtures.py           # human report
  python3 scripts/check_secret_enforce_posture_fixtures.py --check    # CI (exit 1)
  python3 scripts/check_secret_enforce_posture_fixtures.py --self-test
  python3 scripts/check_secret_enforce_posture_fixtures.py --print-query
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "collectors" / "matcher-fixtures" / "secret-enforce-posture"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
EVENTS_PATH = FIXTURE_DIR / "events.ndjson"
SCHEMA_PATH = (
    ROOT / "packages" / "schema" / "schema" / "v1" / "ai-usage-event.schema.json"
)

# Operator remeasure SQL — same filters the quiet-gate / coverage path uses.
# Metadata only: host_ref counts + posture fields. No prompt/secret content.
REMEASURE_SQL = """\
-- AIM-611 / AIM-563 remeasure (AIM-1149): enforce-hash posture coverage
-- Run against pilot Postgres after the calendar quiet window.
-- Expect hosts_enforce_hash >= 1 (and preferably >= 3 pilot hosts) before
-- treating block/confirmed rates as readable. 0 = gate still dark.
SELECT
  COUNT(*)::int AS events_total,
  COUNT(*) FILTER (
    WHERE payload ? 'enforcement_posture'
  )::int AS with_posture,
  COUNT(*) FILTER (
    WHERE payload->'enforcement_posture'->>'policy' = 'loaded'
  )::int AS policy_loaded,
  COUNT(*) FILTER (
    WHERE payload->'enforcement_posture'->>'policy' = 'absent'
  )::int AS policy_absent,
  COUNT(DISTINCT host_ref)::int AS hosts_seen,
  COUNT(DISTINCT host_ref) FILTER (
    WHERE payload->'enforcement_posture'->>'policy' = 'loaded'
  )::int AS hosts_policy_loaded,
  COUNT(DISTINCT host_ref) FILTER (
    WHERE payload->'enforcement_posture'->>'policy' = 'loaded'
      AND payload->'enforcement_posture'->>'mode' = 'enforce'
      AND COALESCE(payload->'enforcement_posture'->>'policy_hash', '') <> ''
  )::int AS hosts_enforce_hash
FROM events
WHERE ts >= now() - interval '14 days'
  AND source = 'endpoint';

-- Per enforce-hash (which bundle is actually on endpoints):
SELECT
  payload->'enforcement_posture'->>'policy_hash' AS policy_hash,
  payload->'enforcement_posture'->>'mode' AS mode,
  COUNT(*)::int AS events,
  COUNT(DISTINCT host_ref)::int AS hosts
FROM events
WHERE ts >= now() - interval '14 days'
  AND source = 'endpoint'
  AND payload->'enforcement_posture'->>'policy' = 'loaded'
GROUP BY 1, 2
ORDER BY hosts DESC, events DESC;
"""


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest root must be an object")
    if not isinstance(data.get("policy"), dict):
        raise ValueError("manifest.policy must be an object")
    if not isinstance(data.get("expected"), dict):
        raise ValueError("manifest.expected must be an object")
    return data


def iter_ndjson(path: Path) -> Iterable[dict[str, Any]]:
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{i}: invalid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"{path}:{i}: event must be a JSON object")
        yield obj


def posture_of(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve enforcement_posture from a top-level event or payload wrapper."""
    if "enforcement_posture" in obj and isinstance(obj["enforcement_posture"], dict):
        return obj["enforcement_posture"]
    payload = obj.get("payload")
    if isinstance(payload, dict) and isinstance(payload.get("enforcement_posture"), dict):
        return payload["enforcement_posture"]
    return None


def is_enforce_hash(p: dict[str, Any] | None) -> bool:
    if not p:
        return False
    if p.get("policy") != "loaded":
        return False
    if p.get("mode") != "enforce":
        return False
    h = p.get("policy_hash")
    return isinstance(h, str) and h.strip() != ""


def aggregate(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Mirror AIM-789 install-path + AIM-611 enforce-hash host counts offline."""
    events_total = 0
    with_posture = 0
    policy_loaded = 0
    policy_absent = 0
    evaluated = 0
    hosts_seen: set[str] = set()
    hosts_with_posture: set[str] = set()
    hosts_policy_loaded: set[str] = set()
    hosts_policy_absent: set[str] = set()
    hosts_enforce_hash: set[str] = set()
    by_mode: Counter[str] = Counter()
    by_policy_hash: Counter[str] = Counter()
    content_leaks: list[str] = []

    forbidden_keys = (
        "prompt",
        "response",
        "content",
        "message",
        "body",
        "tool_input",
        "arguments",
        "raw",
    )

    for obj in events:
        events_total += 1
        host = obj.get("host_ref")
        if isinstance(host, str) and host:
            hosts_seen.add(host)

        for k in forbidden_keys:
            if k in obj and obj[k] not in (None, "", [], {}):
                content_leaks.append(f"top-level {k} on event_id={obj.get('event_id')}")

        p = posture_of(obj)
        if not p:
            continue
        with_posture += 1
        if isinstance(host, str) and host:
            hosts_with_posture.add(host)

        policy = p.get("policy")
        if policy == "loaded":
            policy_loaded += 1
            if isinstance(host, str) and host:
                hosts_policy_loaded.add(host)
            mode = p.get("mode") or "unknown"
            by_mode[str(mode)] += 1
            ph = p.get("policy_hash")
            if isinstance(ph, str) and ph:
                by_policy_hash[ph] += 1
            if is_enforce_hash(p) and isinstance(host, str) and host:
                hosts_enforce_hash.add(host)
        elif policy == "absent":
            policy_absent += 1
            if isinstance(host, str) and host:
                hosts_policy_absent.add(host)

        if p.get("evaluated") is True:
            evaluated += 1

    hosts_enforce = len(hosts_enforce_hash)
    dark = hosts_enforce == 0
    return {
        "events_total": events_total,
        "with_posture": with_posture,
        "policy_loaded": policy_loaded,
        "policy_absent": policy_absent,
        "evaluated": evaluated,
        "hosts_seen": len(hosts_seen),
        "hosts_with_posture": len(hosts_with_posture),
        "hosts_policy_loaded": len(hosts_policy_loaded),
        "hosts_policy_absent": len(hosts_policy_absent),
        "hosts_enforce_hash": hosts_enforce,
        "by_mode": dict(by_mode),
        "by_policy_hash": dict(by_policy_hash),
        "content_leaks": content_leaks,
        "dark": dark,
        "verdict": "DARK" if dark else "COVERED",
        "statement": (
            "DARK — 0 hosts with enforce-hash posture "
            "(policy=loaded, mode=enforce, policy_hash set). "
            "Quiet-gate measurements are unreadable (AIM-611 failure mode)."
            if dark
            else (
                f"COVERED — {hosts_enforce} host(s) emit enforce-hash posture; "
                "measurement path is not dark."
            )
        ),
    }


def validate_schema(events: list[dict[str, Any]]) -> list[str]:
    if not SCHEMA_PATH.is_file():
        return [f"schema missing: {SCHEMA_PATH}"]
    try:
        import jsonschema
    except ImportError:
        return []  # optional offline; CI has jsonschema via requirements-dev
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    errs: list[str] = []
    for i, ev in enumerate(events, 1):
        for e in sorted(validator.iter_errors(ev), key=lambda x: list(x.path)):
            path = ".".join(str(p) for p in e.path) or "(root)"
            errs.append(f"event[{i}] {path}: {e.message}")
    return errs


def check_manifest_expectations(agg: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for key in (
        "events_total",
        "hosts_seen",
        "hosts_with_posture",
        "hosts_policy_loaded",
        "hosts_policy_absent",
        "hosts_enforce_hash",
    ):
        if key not in expected:
            continue
        if agg.get(key) != expected[key]:
            failures.append(
                f"expected.{key}={expected[key]} but aggregate has {agg.get(key)}"
            )
    if "by_mode" in expected:
        if dict(agg.get("by_mode") or {}) != dict(expected["by_mode"]):
            failures.append(
                f"expected.by_mode={expected['by_mode']} got {agg.get('by_mode')}"
            )
    if "by_policy_hash" in expected:
        if dict(agg.get("by_policy_hash") or {}) != dict(expected["by_policy_hash"]):
            failures.append(
                f"expected.by_policy_hash={expected['by_policy_hash']} "
                f"got {agg.get('by_policy_hash')}"
            )
    return failures


def run_check(check: bool = False) -> int:
    problems: list[str] = []
    if not MANIFEST_PATH.is_file():
        problems.append(f"missing manifest: {MANIFEST_PATH}")
    if not EVENTS_PATH.is_file():
        problems.append(f"missing events: {EVENTS_PATH}")
    if problems:
        for p in problems:
            print(f"FAIL {p}")
        return 1

    manifest = load_manifest()
    events = list(iter_ndjson(EVENTS_PATH))
    if not events:
        print("FAIL events.ndjson is empty")
        return 1

    schema_errs = validate_schema(events)
    for e in schema_errs:
        problems.append(f"schema: {e}")

    agg = aggregate(events)
    policy = manifest["policy"]
    min_hosts = int(policy.get("min_hosts_enforce_hash", 1))

    if agg["content_leaks"]:
        for leak in agg["content_leaks"]:
            problems.append(f"privacy: {leak}")

    if agg["hosts_enforce_hash"] < min_hosts:
        problems.append(
            f"hosts_enforce_hash={agg['hosts_enforce_hash']} < min={min_hosts} "
            "(dark / insufficient enforce-hash coverage on fixture set)"
        )
    if agg["dark"]:
        problems.append("aggregate verdict is DARK (0 enforce-hash hosts)")

    # The AIM-611 dark shape is specifically "0 hosts + policy absent dominance".
    if (
        agg["hosts_enforce_hash"] == 0
        and agg["policy_loaded"] == 0
        and (agg["policy_absent"] > 0 or agg["with_posture"] == 0)
    ):
        problems.append(
            "fixture set matches the AIM-611 dark shape: "
            "0 hosts enforce-hash and policy=absent / no loaded posture"
        )

    exp_failures = check_manifest_expectations(agg, manifest["expected"])
    problems.extend(exp_failures)

    print("# AIM-1149 secret-enforce posture fixtures")
    print()
    print(f"events: {EVENTS_PATH.relative_to(ROOT)}")
    print(f"verdict: {agg['verdict']}")
    print(f"statement: {agg['statement']}")
    print()
    print("| measure | value |")
    print("| --- | ---: |")
    for key in (
        "events_total",
        "with_posture",
        "policy_loaded",
        "policy_absent",
        "evaluated",
        "hosts_seen",
        "hosts_with_posture",
        "hosts_policy_loaded",
        "hosts_policy_absent",
        "hosts_enforce_hash",
    ):
        print(f"| {key} | {agg[key]} |")
    print()
    print(f"by_mode: {agg['by_mode']}")
    print(f"by_policy_hash: {agg['by_policy_hash']}")
    print()

    if problems:
        print(f"FAIL ({len(problems)})")
        for p in problems:
            print(f"  - {p}")
        return 1

    print("PASS — fixture set keeps enforce-hash coverage non-zero")
    if not check:
        print("(report-only; pass --check for CI exit semantics — already green)")
    return 0


def _sample_event(
    host: str,
    *,
    policy: str = "loaded",
    mode: str | None = "enforce",
    policy_hash: str | None = "fixture-hash",
    evaluated: bool = True,
) -> dict[str, Any]:
    posture: dict[str, Any] = {"policy": policy, "evaluated": evaluated}
    if policy == "loaded":
        if mode is not None:
            posture["mode"] = mode
        if policy_hash is not None:
            posture["policy_hash"] = policy_hash
    return {
        "schema_version": "1.11",
        "event_id": "00000000-0000-4000-8000-000000000099",
        "ts": "2026-08-09T00:00:00Z",
        "host_ref": host,
        "user_ref": None,
        "tool": "claude_code",
        "tool_version": "1.0.0",
        "model": None,
        "provider": None,
        "session_id": "self-test-session",
        "repo_ref": None,
        "match_flags": [],
        "enforcement_posture": posture,
        "source": "endpoint",
    }


def self_test() -> int:
    """Prove dark shapes fail and a single enforce-hash host passes."""
    failed = 0

    def check_case(label: str, events: list[dict[str, Any]], expect_dark: bool) -> None:
        nonlocal failed
        agg = aggregate(events)
        ok = agg["dark"] is expect_dark
        # Exit semantics for CI: dark must never be "fine".
        exit_ok = (not agg["dark"]) or (agg["hosts_enforce_hash"] == 0)
        if not ok or not exit_ok:
            failed += 1
            print(
                f"FAIL {label}: dark={agg['dark']} hosts_enforce_hash="
                f"{agg['hosts_enforce_hash']} want_dark={expect_dark}"
            )
        else:
            print(
                f"ok   {label}: dark={agg['dark']} "
                f"hosts_enforce_hash={agg['hosts_enforce_hash']}"
            )

    # The AIM-611 live failure mode: telemetry present, only policy=absent.
    check_case(
        "all policy=absent is dark",
        [
            _sample_event("a" * 64, policy="absent", mode=None, policy_hash=None),
            _sample_event("b" * 64, policy="absent", mode=None, policy_hash=None),
        ],
        expect_dark=True,
    )
    # Shadow bake only (pre-AIM-296 posture) — not enforce-hash.
    check_case(
        "shadow-only loaded is dark for enforce-hash",
        [
            _sample_event(
                "a" * 64, mode="shadow", policy_hash="aim117-shadow-bake-fixture"
            ),
        ],
        expect_dark=True,
    )
    # Missing posture entirely.
    bare = _sample_event("a" * 64)
    del bare["enforcement_posture"]
    check_case("no posture marker is dark", [bare], expect_dark=True)
    # Loaded enforce without policy_hash — not attributable (not enforce-hash).
    check_case(
        "enforce without policy_hash is dark",
        [_sample_event("a" * 64, mode="enforce", policy_hash=None)],
        expect_dark=True,
    )
    # Single host with enforce-hash is enough for the fixture floor.
    check_case(
        "one enforce-hash host is covered",
        [_sample_event("a" * 64, mode="enforce", policy_hash="aim1149-fixture")],
        expect_dark=False,
    )
    # Mixed fleet: absent + shadow + one enforce must still cover.
    check_case(
        "mixed fleet with one enforce-hash is covered",
        [
            _sample_event("a" * 64, policy="absent", mode=None, policy_hash=None),
            _sample_event(
                "b" * 64, mode="shadow", policy_hash="aim117-shadow-bake-fixture"
            ),
            _sample_event("c" * 64, mode="enforce", policy_hash="aim1149-fixture"),
        ],
        expect_dark=False,
    )

    # Aggregate must count distinct hosts, not events.
    multi = [
        _sample_event("a" * 64, mode="enforce", policy_hash="h1"),
        _sample_event("a" * 64, mode="enforce", policy_hash="h1"),
        _sample_event("b" * 64, mode="enforce", policy_hash="h1"),
    ]
    agg = aggregate(multi)
    if agg["hosts_enforce_hash"] != 2 or agg["events_total"] != 3:
        failed += 1
        print(
            f"FAIL distinct hosts: events={agg['events_total']} "
            f"hosts_enforce_hash={agg['hosts_enforce_hash']} want 3/2"
        )
    else:
        print("ok   distinct host count under multi-event host")

    # Privacy: content-bearing top-level keys are flagged.
    leaky = _sample_event("a" * 64)
    leaky["prompt"] = "should-never-be-here"
    leaks = aggregate([leaky])["content_leaks"]
    if not leaks:
        failed += 1
        print("FAIL content leak not detected")
    else:
        print("ok   content leak detection")

    # is_enforce_hash pure cases
    pure = [
        ({"policy": "loaded", "mode": "enforce", "policy_hash": "x"}, True),
        ({"policy": "loaded", "mode": "shadow", "policy_hash": "x"}, False),
        ({"policy": "absent", "evaluated": False}, False),
        ({"policy": "loaded", "mode": "enforce", "policy_hash": ""}, False),
        (None, False),
    ]
    for p, want in pure:
        got = is_enforce_hash(p)
        if got is not want:
            failed += 1
            print(f"FAIL is_enforce_hash({p})={got} want {want}")
        else:
            print(f"ok   is_enforce_hash({p}) -> {got}")

    # Fixture pack on disk must itself pass (aliveness of the package).
    rc = run_check(check=True)
    if rc != 0:
        failed += 1
        print("FAIL on-disk fixture pack failed --check")
    else:
        print("ok   on-disk fixture pack passes --check")

    # Mutating the on-disk pack to all-absent must go red (proves the rule is alive).
    original_events = EVENTS_PATH.read_text(encoding="utf-8")
    original_manifest = MANIFEST_PATH.read_text(encoding="utf-8")
    try:
        dark_events = [
            _sample_event(
                f"{i:064x}"[:64],
                policy="absent",
                mode=None,
                policy_hash=None,
            )
            for i in range(1, 4)
        ]
        EVENTS_PATH.write_text(
            "\n".join(json.dumps(e, separators=(",", ":")) for e in dark_events) + "\n",
            encoding="utf-8",
        )
        # Align expected counts so only the dark-verdict rule (min hosts / DARK)
        # fails — not a spurious expected-count mismatch.
        man = json.loads(original_manifest)
        man_copy = deepcopy(man)
        man_copy["expected"] = {
            "events_total": 3,
            "hosts_seen": 3,
            "hosts_with_posture": 3,
            "hosts_policy_loaded": 0,
            "hosts_policy_absent": 3,
            "hosts_enforce_hash": 0,
            "by_mode": {},
            "by_policy_hash": {},
        }
        MANIFEST_PATH.write_text(json.dumps(man_copy, indent=2) + "\n", encoding="utf-8")
        rc_dark = run_check(check=True)
        if rc_dark == 0:
            failed += 1
            print("FAIL mutated all-absent fixture pack still PASSED (rule dead)")
        else:
            print("ok   mutated all-absent fixture pack FAILS (rule alive)")
    finally:
        EVENTS_PATH.write_text(original_events, encoding="utf-8")
        MANIFEST_PATH.write_text(original_manifest, encoding="utf-8")

    # Ensure restore left pack green.
    if run_check(check=True) != 0:
        failed += 1
        print("FAIL fixture pack not restored after self-test mutation")
    else:
        print("ok   fixture pack restored after mutation")

    print()
    if failed:
        print(f"self-test FAILED ({failed})")
        return 1
    print("self-test PASSED")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="CI mode: exit 1 on dark / expectation / schema failures",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Prove dark shapes fail and the fixture pack stays green",
    )
    parser.add_argument(
        "--print-query",
        action="store_true",
        help="Print the operator remeasure SQL and exit 0",
    )
    args = parser.parse_args(argv)

    if args.print_query:
        sys.stdout.write(REMEASURE_SQL)
        if not REMEASURE_SQL.endswith("\n"):
            sys.stdout.write("\n")
        return 0
    if args.self_test:
        return self_test()
    return run_check(check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
