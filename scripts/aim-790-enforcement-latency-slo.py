#!/usr/bin/env python3
"""AIM-790 dogfood: endpoint enforcement decision latency SLO (p95 < 200 ms).

Runs the shipped Claude Code hook decision path against synthetic prompts
(secret-scan + clean) and asserts the measured p95 stays under the design
budget. Emits a JSON report suitable for CI.

Usage:
  python3 scripts/aim-790-enforcement-latency-slo.py
  python3 scripts/aim-790-enforcement-latency-slo.py --samples 100 --budget-ms 200

Exit 0 when p95 ≤ budget and enough samples collected; non-zero otherwise.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collectors" / "claude-code"))

# Synthetic AWS access-key shape used in unit tests (dead example token).
SECRET_PROMPT = "here is the key AKIAIOSFODNN7EXAMPLE please use it"
CLEAN_PROMPT = "refactor the parser into pure functions please"
# Longer-ish clean prompt to exercise matcher work without secrets.
NOISY_CLEAN = ("please review this module for style " * 40).strip()

ENFORCE_BUNDLE = ROOT / "deploy" / "enforcement" / "enforcement.enforce.json"
SHADOW_BUNDLE = ROOT / "deploy" / "enforcement" / "enforcement.shadow.json"

DEFAULT_BUDGET_MS = 200  # design SLO (p95)
DEFAULT_SAMPLES = 60     # enough for a stable p95 in CI
FAIL_OPEN_TIMEOUT_MS = 500  # separate hard budget — documented, not asserted here


def _percentile(sorted_vals: list[int], p: float) -> float:
    """Linear-interpolation percentile (stable for small CI sample sizes)."""
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    k = (len(sorted_vals) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_vals[int(k)])
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


def _run_once(bundle: Path, prompt: str, session_id: str) -> dict:
    from aim_collector import hook, spool

    state = tempfile.mkdtemp(prefix="aim790-state-")
    os.environ["AIM_STATE_DIR"] = state
    os.environ["AIM_ENFORCEMENT_FILE"] = str(bundle)
    captured: list[dict] = []
    with mock.patch.object(spool, "append", side_effect=lambda evs: captured.extend(evs)), \
         mock.patch.object(spool, "flush", return_value={}):
        code, out = hook.run(json.dumps({
            "hook_event_name": "UserPromptSubmit",
            "session_id": session_id,
            "prompt": prompt,
        }).encode())
    if code != 0:
        raise AssertionError(f"hook exit {code} (fail-open contract broken)")
    if not captured:
        raise AssertionError("hook produced no event")
    pos = captured[0].get("enforcement_posture") or {}
    if "enforcement_latency_ms" not in pos:
        raise AssertionError(
            f"missing enforcement_latency_ms on posture: {pos!r}"
        )
    return {
        "latency_ms": int(pos["enforcement_latency_ms"]),
        "evaluated": bool(pos.get("evaluated")),
        "action": (captured[0].get("enforcement") or {}).get("action"),
        "stdout_nonempty": bool(out.strip()),
        "policy": pos.get("policy"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--samples", type=int, default=DEFAULT_SAMPLES,
                    help=f"total decision samples (default {DEFAULT_SAMPLES})")
    ap.add_argument("--budget-ms", type=int, default=DEFAULT_BUDGET_MS,
                    help=f"p95 budget in ms (default {DEFAULT_BUDGET_MS})")
    ap.add_argument("--bundle", type=Path, default=ENFORCE_BUNDLE,
                    help="enforcement policy bundle path")
    ap.add_argument("--shadow", action="store_true",
                    help="use the shadow bundle instead of enforce")
    args = ap.parse_args()

    bundle = SHADOW_BUNDLE if args.shadow else args.bundle
    if not bundle.is_file():
        print(json.dumps({"error": "bundle_missing", "path": str(bundle)}),
              file=sys.stderr)
        return 2

    n = max(10, args.samples)
    # Mix: ~half secret-scan path (the SLO dogfood target), rest clean/noisy.
    n_secret = max(1, n // 2)
    n_clean = max(1, n // 4)
    n_noisy = n - n_secret - n_clean

    cases: list[tuple[str, str]] = (
        [("secret", SECRET_PROMPT)] * n_secret
        + [("clean", CLEAN_PROMPT)] * n_clean
        + [("noisy_clean", NOISY_CLEAN)] * n_noisy
    )

    samples: list[dict] = []
    for i, (kind, prompt) in enumerate(cases):
        samples.append({
            "kind": kind,
            **_run_once(bundle, prompt, session_id=f"aim790-{kind}-{i}"),
        })

    latencies = [s["latency_ms"] for s in samples]
    latencies_sorted = sorted(latencies)
    p50 = _percentile(latencies_sorted, 0.50)
    p95 = _percentile(latencies_sorted, 0.95)
    budget = args.budget_ms
    breaches = sum(1 for v in latencies if v > budget)
    secret_lats = [s["latency_ms"] for s in samples if s["kind"] == "secret"]
    secret_p95 = _percentile(sorted(secret_lats), 0.95) if secret_lats else float("nan")

    try:
        bundle_label = str(bundle.relative_to(ROOT))
    except ValueError:
        bundle_label = str(bundle)

    report = {
        "kind": "aim-790-enforcement-latency-slo",
        "bundle": bundle_label,
        "slo_ms": budget,
        "fail_open_timeout_ms": FAIL_OPEN_TIMEOUT_MS,
        "samples": len(latencies),
        "by_kind": {
            k: sum(1 for s in samples if s["kind"] == k)
            for k in ("secret", "clean", "noisy_clean")
        },
        "p50_ms": round(p50, 3),
        "p95_ms": round(p95, 3),
        "secret_p95_ms": round(secret_p95, 3) if not math.isnan(secret_p95) else None,
        "max_ms": max(latencies),
        "min_ms": min(latencies),
        "mean_ms": round(statistics.fmean(latencies), 3),
        "breaches": breaches,
        "within_slo": p95 <= budget and secret_p95 <= budget,
        "note": (
            f"p95 {p95:.1f} ms (secret-scan p95 {secret_p95:.1f} ms) "
            f"vs budget {budget} ms; fail-open timeout {FAIL_OPEN_TIMEOUT_MS} ms is separate."
        ),
    }
    print(json.dumps(report, indent=2))

    if not report["within_slo"]:
        print(
            f"FAIL: p95 {p95:.1f} ms or secret p95 {secret_p95:.1f} ms "
            f"exceeds budget {budget} ms",
            file=sys.stderr,
        )
        return 1
    if not all(s["evaluated"] for s in samples):
        print("FAIL: some samples were not evaluated", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
