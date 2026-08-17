#!/usr/bin/env python3
"""Credential-shaped-tool-call precision/recall validation.

Evaluates the shipped guardrail ruleset (policies/guardrail/v1) against the
labeled tool-name corpus at
services/guardrail/tests/fixtures/credential_shaped_tool_names.json.

Why: pilot traffic (30k events, 6k tool_use) has zero mcp_call rows and zero
credential-shaped tool names, so live hit rate cannot measure precision. This
corpus supplies synthetic TP/TN cases (MCP + built-in) including the bare
``token`` false-positive surface (count_tokens, pagination, tokenizer).

Exit code is non-zero if any case is misclassified (CI-usable regression gate).

Usage:
  python3 scripts/credential-shaped-precision.py
  python3 scripts/credential-shaped-precision.py --json-report /tmp/out.json
  python3 scripts/credential-shaped-precision.py --pilot-jsonl events.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "services" / "guardrail" / "src"))

from guardrail.engine import Engine  # noqa: E402
from guardrail.rules import load_ruleset  # noqa: E402

RULES_DIR = REPO / "policies" / "guardrail" / "v1"
CORPUS = (
    REPO
    / "services"
    / "guardrail"
    / "tests"
    / "fixtures"
    / "credential_shaped_tool_names.json"
)
RULE_ID = "credential-shaped-tool-call"


def _base_event(tool_name: str, action_class: str, mcp_server: str | None) -> dict:
    call = {
        "tool_name": tool_name,
        "action_class": action_class,
        "count": 1,
    }
    if mcp_server is not None:
        call["mcp_server"] = mcp_server
    return {
        "schema_version": "1.1",
        "event_id": "11111111-1111-4111-8111-000000000001",
        "ts": "2026-08-01T12:00:00Z",
        "host_ref": "a" * 64,
        "user_ref": "b" * 64,
        "tool": "claude_code",
        "tool_version": "1.0.0",
        "provider": "anthropic",
        "model": "claude-sonnet-4-5",
        "session_id": "sess-aim572",
        "tokens_in": 1,
        "tokens_out": 1,
        "repo_ref": "c" * 64,
        "match_flags": [],
        "source": "endpoint",
        "event_type": "tool_use",
        "tool_calls": [call],
    }


def evaluate_corpus(engine: Engine) -> dict:
    corpus = json.loads(CORPUS.read_text())
    cases = corpus["cases"]
    tp = fp = tn = fn = 0
    misses: list[str] = []
    false_fires: list[dict] = []
    for c in cases:
        ev = _base_event(c["tool_name"], c["action_class"], c.get("mcp_server"))
        findings, _audit = engine.evaluate(ev)
        fired = any(f.get("rule_id") == RULE_ID for f in findings)
        if c["kind"] == "positive":
            if fired:
                tp += 1
            else:
                fn += 1
                misses.append(c["id"])
        else:
            if fired:
                fp += 1
                false_fires.append({"id": c["id"], "tool_name": c["tool_name"]})
            else:
                tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rule_id": RULE_ID,
        "corpus": str(CORPUS.relative_to(REPO)),
        "positives": tp + fn,
        "negatives": fp + tn,
        "true_positives": tp,
        "false_negatives": fn,
        "true_negatives": tn,
        "false_positives": fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "misses": misses,
        "false_fires": false_fires,
        "needles": (engine.ruleset.settings or {}).get("credential_tool_name_substrings"),
    }


def _iter_pilot_events(jsonl: Path | None, dsn: str | None, limit: int | None):
    """Yield engine-ready events from JSONL (one object per line) or Postgres."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "aim441", REPO / "scripts" / "ruleset-precision.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    if jsonl:
        return mod.load_events_jsonl(jsonl)
    if dsn:
        return mod.load_events_pg(dsn, limit)
    raise ValueError("pilot scan requires --pilot-jsonl or --dsn")


def pilot_scan(engine: Engine, jsonl: Path | None, dsn: str | None, limit: int | None) -> dict:
    """Optional re-scan of pilot events for live hit counts (no labels)."""
    if not jsonl and not dsn:
        return {"skipped": True, "reason": "no --pilot-jsonl / --dsn"}

    hits = 0
    events_n = 0
    tool_use_n = 0
    mcp_n = 0
    name_hits: Counter = Counter()
    for ev in _iter_pilot_events(jsonl, dsn, limit):
        events_n += 1
        if ev.get("event_type") == "tool_use" or ev.get("tool_calls"):
            tool_use_n += 1
        for c in ev.get("tool_calls") or []:
            if isinstance(c, dict) and (
                c.get("action_class") == "mcp_call" or c.get("mcp_server")
            ):
                mcp_n += 1
        findings, _ = engine.evaluate(ev)
        for f in findings:
            if f.get("rule_id") != RULE_ID:
                continue
            hits += 1
            for d in f.get("details") or []:
                actual = d.get("actual")
                if isinstance(actual, list):
                    for a in actual:
                        if isinstance(a, dict) and a.get("tool_name"):
                            name_hits[a["tool_name"]] += 1
    return {
        "events": events_n,
        "tool_use_or_calls": tool_use_n,
        "mcp_call_rows_seen": mcp_n,
        "credential_shaped_hits": hits,
        "hit_rate": round(hits / events_n, 6) if events_n else 0.0,
        "matched_tool_names": dict(name_hits.most_common(50)),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json-report", type=Path, default=None)
    ap.add_argument("--pilot-jsonl", type=Path, default=None)
    ap.add_argument("--dsn", default=None)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    engine = Engine(load_ruleset(RULES_DIR))
    report = evaluate_corpus(engine)

    if args.pilot_jsonl or args.dsn:
        report["pilot"] = pilot_scan(engine, args.pilot_jsonl, args.dsn, args.limit)

    ok = report["false_positives"] == 0 and report["false_negatives"] == 0
    print(
        f"credential-shaped-tool-call  precision={report['precision']:.4f}  "
        f"recall={report['recall']:.4f}  "
        f"TP={report['true_positives']} FP={report['false_positives']} "
        f"TN={report['true_negatives']} FN={report['false_negatives']}"
    )
    if report["misses"]:
        print("misses:", ", ".join(report["misses"]))
    if report["false_fires"]:
        print("false_fires:", json.dumps(report["false_fires"]))
    if report.get("pilot"):
        print("pilot:", json.dumps(report["pilot"], indent=2))
    print("status:", "PASS" if ok else "FAIL")

    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(report, indent=2) + "\n")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
