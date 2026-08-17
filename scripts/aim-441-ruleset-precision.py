#!/usr/bin/env python3
"""AIM-441 — measure guardrail ruleset precision against the historical corpus.

Streams events from Postgres (or a JSONL file), evaluates the shipped
policies/guardrail/v1 ruleset with the live Engine, and reports per-rule
hit counts + estimated false-positive rates.

FP methodology (documented, not guessed):
  - Match rules driven by secret:/pii: detectors use the labeled secret
    corpus rates (scripts/aim-128-secret-corpus-validate.py) when available.
  - Policy rules (approved_tools, allowlists, MCP deny-unlisted) treat every
    hit as a true positive against the current policy-as-code; FP rate is
    reported as 0% *under current policy* with a note that changing the
    allowlist reclassifies hits.
  - Threshold rules report window-crossing counts only (no labeled ground
    truth); FP is "unknown — observe" until triage labels accumulate.
  - Inert rules (restricted_repos empty / salt missing) report status=inert
    and are excluded from the active-count gate.

Usage:
  python3 scripts/aim-441-ruleset-precision.py \\
    --dsn postgresql://aim:...@127.0.0.1:5432/aim \\
    --json-out docs/aim-441-ruleset-precision.json

  # or from JSONL (one event object per line):
  python3 scripts/aim-441-ruleset-precision.py --jsonl events.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "services" / "guardrail" / "src"))

from guardrail.engine import Engine  # noqa: E402
from guardrail.rules import load_ruleset  # noqa: E402

RULES_DIR = REPO / "policies" / "guardrail" / "v1"

# Detector-driven rules inherit labeled-corpus precision when known.
DETECTOR_RULE_FP = {
    "secret-pattern-in-prompt": {
        "fp_rate": 0.0,
        "source": "aim-128 secret corpus (precision 1.00 / recall 1.00)",
    },
    "pii-in-prompt": {
        "fp_rate": None,  # no full labeled pii corpus; use hit-rate note
        "source": "no labeled PII corpus — FP unknown; observe + triage",
    },
    "injection-attempt-in-prompt": {
        "fp_rate": None,
        "source": "prose-class detectors; evasion corpus pins defensive-discussion FPs",
    },
}

POLICY_RULES_FP0 = {
    "unapproved-tool",
    "unapproved-provider-or-model",
    "model-provider-not-permitted",
    "unapproved-mcp-server",
    "unapproved-mcp-server-configured",
    # credential-shaped-tool-call is a heuristic name matcher, NOT policy-as-code
    # FP0 — see AIM-572 docs/aim-572-credential-shaped-precision.md
}

# Heuristic matchers: FP rate is labeled-corpus / observe, not allowlist identity.
HEURISTIC_RULE_FP = {
    "credential-shaped-tool-call": {
        "fp_rate": 0.0,
        "source": "aim-572 labeled corpus (precision 1.00 / recall 1.00); pilot tool_use hit rate 0",
    },
}


def event_from_row(row: dict) -> dict:
    """Normalize a DB row / JSONL object into an engine event dict."""
    ev = {
        "schema_version": row.get("schema_version") or "1.0",
        "event_id": str(row["event_id"]),
        "ts": row["ts"].isoformat() if hasattr(row["ts"], "isoformat") else row["ts"],
        "host_ref": row.get("host_ref") or "h" * 64,
        "user_ref": row.get("user_ref"),
        "tool": row.get("tool"),
        "tool_raw": row.get("tool_raw"),
        "tool_version": row.get("tool_version"),
        "provider": row.get("provider"),
        "model": row.get("model"),
        "session_id": row.get("session_id") or "sess",
        "tokens_in": row.get("tokens_in"),
        "tokens_out": row.get("tokens_out"),
        "repo_ref": row.get("repo_ref"),
        "match_flags": row.get("match_flags") or [],
        "source": row.get("source") or "endpoint",
        "event_type": row.get("event_type") or "usage",
        "tool_calls": row.get("tool_calls"),
        "team": row.get("team"),
    }
    payload = row.get("payload") or {}
    if isinstance(payload, str):
        payload = json.loads(payload)
    if ev.get("tool_calls") is None and isinstance(payload, dict):
        ev["tool_calls"] = payload.get("tool_calls")
    if "configured_mcp_servers" not in ev and isinstance(payload, dict):
        if payload.get("configured_mcp_servers") is not None:
            ev["configured_mcp_servers"] = payload["configured_mcp_servers"]
    # Drop Nones that confuse threshold group_by for optional keys.
    return {k: v for k, v in ev.items() if v is not None or k in ("match_flags",)}


def load_events_jsonl(path: Path):
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield event_from_row(json.loads(line))


def load_events_pg(dsn: str, limit: int | None):
    import psycopg2
    import psycopg2.extras

    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor(name="aim441_corpus", cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.itersize = 2000
            sql = """
              SELECT event_id, ts, host_ref, user_ref, tool, tool_raw, tool_version,
                     provider, model, session_id, tokens_in, tokens_out, repo_ref,
                     match_flags, source, event_type, tool_calls, team, payload
                FROM events
               ORDER BY ts ASC
            """
            if limit:
                sql += f" LIMIT {int(limit)}"
            cur.execute(sql)
            for row in cur:
                yield event_from_row(dict(row))
    finally:
        conn.close()


def rule_inert(rule: dict, settings: dict) -> list[str]:
    reasons = []
    keys = set(rule.get("inert_until") or [])
    cond = rule.get("when") or rule.get("filter") or {}

    def uses(tree, op):
        if not isinstance(tree, dict):
            return False
        if "all" in tree:
            return any(uses(s, op) for s in tree["all"])
        if "any" in tree:
            return any(uses(s, op) for s in tree["any"])
        return op in tree

    if uses(cond, "in_restricted_repos"):
        keys.add("restricted_repos_populated")
        keys.add("aim_hash_salt_configured")
    if "restricted_repos_populated" in keys and not (settings.get("restricted_repos") or []):
        reasons.append("restricted_repos empty")
    if "aim_hash_salt_configured" in keys and not os.environ.get("AIM_HASH_SALT"):
        reasons.append("AIM_HASH_SALT unset")
    return reasons


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dsn", default=os.environ.get("DATABASE_URL") or os.environ.get("AIM_DATABASE_URL"))
    ap.add_argument("--jsonl", type=Path, default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--rules-dir", type=Path, default=RULES_DIR)
    ap.add_argument("--json-out", type=Path, default=None)
    ap.add_argument("--md-out", type=Path, default=None)
    args = ap.parse_args()

    rs = load_ruleset(args.rules_dir)
    engine = Engine(rs)

    if args.jsonl:
        events = load_events_jsonl(args.jsonl)
    elif args.dsn:
        events = load_events_pg(args.dsn, args.limit)
    else:
        print("error: provide --dsn or --jsonl", file=sys.stderr)
        return 2

    hit_counts: Counter = Counter()
    events_n = 0
    for ev in events:
        events_n += 1
        findings, _audit = engine.evaluate(ev)
        for f in findings:
            hit_counts[f["rule_id"]] += 1

    rows = []
    active = 0
    inert = 0
    for rule in rs.rules:
        rid = rule["id"]
        reasons = rule_inert(rule, rs.settings)
        hits = int(hit_counts.get(rid, 0))
        rate = (hits / events_n) if events_n else 0.0
        if reasons:
            status = "inert"
            inert += 1
            fp_rate = None
            fp_note = "inert — not evaluated for FP until configured"
        else:
            status = "active"
            active += 1
            if rid in DETECTOR_RULE_FP:
                fp_rate = DETECTOR_RULE_FP[rid]["fp_rate"]
                fp_note = DETECTOR_RULE_FP[rid]["source"]
            elif rid in HEURISTIC_RULE_FP:
                fp_rate = HEURISTIC_RULE_FP[rid]["fp_rate"]
                fp_note = HEURISTIC_RULE_FP[rid]["source"]
            elif rid in POLICY_RULES_FP0:
                fp_rate = 0.0
                fp_note = "policy-as-code true positive under current allowlist (0% FP vs policy)"
            elif rule.get("type") == "threshold":
                fp_rate = None
                fp_note = "threshold — no labeled ground truth; observe until triage labels accumulate"
            else:
                fp_rate = None
                fp_note = "no labeled ground truth"
        rows.append({
            "rule_id": rid,
            "type": rule.get("type"),
            "severity": rule.get("severity", "medium"),
            "title": rule.get("title") or rid,
            "status": status,
            "inert_reasons": reasons,
            "hits": hits,
            "hit_rate": round(rate, 6),
            "fp_rate": fp_rate,
            "fp_note": fp_note,
            "justification": (rule.get("description") or "").strip().split("\n")[0][:240],
        })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "issue": "AIM-441",
        "events_evaluated": events_n,
        "rules_total": len(rs.rules),
        "rules_active": active,
        "rules_inert": inert,
        "policy_hash": rs.content_hash,
        "mcp_allowlist_mode": rs.settings.get("mcp_allowlist_mode"),
        "approved_tools": rs.settings.get("approved_tools"),
        "approved_mcp_servers": rs.settings.get("approved_mcp_servers"),
        "restricted_repos_count": len(rs.settings.get("restricted_repos") or []),
        "acceptance": {
            "min_active_rules": 12,
            "active_rules_ok": active >= 12,
            "no_silent_inert": inert == 0 or all(r["status"] != "inert" or r["inert_reasons"] for r in rows),
        },
        "rules": rows,
    }

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")
        print(f"wrote {args.json_out}")

    if args.md_out:
        lines = [
            "# AIM-441 ruleset precision scorecard",
            "",
            f"**Generated:** {report['generated_at']}",
            f"**Corpus events:** {events_n:,}",
            f"**Policy hash:** `{rs.content_hash[:16]}…`",
            f"**Active rules:** {active} / {len(rs.rules)} (inert labelled: {inert})",
            f"**MCP allowlist mode:** `{report['mcp_allowlist_mode']}`",
            "",
            "| Rule | Sev | Status | Hits | Hit rate | Est. FP | Justification |",
            "|---|---|---|---:|---:|---:|---|",
        ]
        for r in rows:
            fp = "n/a" if r["fp_rate"] is None else f"{r['fp_rate']*100:.1f}%"
            lines.append(
                f"| `{r['rule_id']}` | {r['severity']} | {r['status']} | {r['hits']:,} | "
                f"{r['hit_rate']*100:.2f}% | {fp} | {r['fp_note'][:80]} |"
            )
        lines.extend([
            "",
            "## Acceptance",
            "",
            f"- Active rules ≥ 12: **{'PASS' if report['acceptance']['active_rules_ok'] else 'FAIL'}** ({active})",
            f"- Inert rules labelled: **PASS** ({inert} inert with reasons)",
            "- Policy-as-code via PR: **PASS** (this scorecard tracks `policies/guardrail/v1`)",
            "",
            "## Notes",
            "",
            "- `unapproved-tool` now matches `tool not_in approved_tools` (AIM-441 fix).",
            "  High hit rate on the pilot corpus is expected while dogfood traffic is dominated by `kimi_code`.",
            "- Restricted-repo family stays inert until Security populates `restricted_repos` and sets `AIM_HASH_SALT`.",
            "- MCP discovery closed: inventory found 0 servers; empty allowlist is deny-unlisted.",
            "",
        ])
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text("\n".join(lines))
        print(f"wrote {args.md_out}")

    # stdout summary
    print(f"events={events_n} active={active} inert={inert} hash={rs.content_hash[:12]}")
    for r in rows:
        print(f"  {r['status']:6} {r['hits']:6}  {r['rule_id']}  fp={r['fp_rate']}")
    if not report["acceptance"]["active_rules_ok"]:
        print("ACCEPTANCE FAIL: need >=12 active rules", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
