#!/usr/bin/env python3
"""Would-block report (AIM-113): what traffic WOULD have been blocked if the
exported blocklist (export_blocklist.py) had been enforced on the corporate
proxy during the observation window.

Reads canonical AI Usage Events (JSONL, one event per line — e.g. an export
of the events table) and aggregates the events already flagged
`policy:unapproved-tool` by the collectors, joined back against
endpoints.json to determine which blocklist tier would have caught them.

Three buckets, reported separately (honesty about coverage matters more
than a big number):

  enforce      — rule is in the default blocklist export (employee-tool
                 categories): this traffic WOULD have been blocked.
  review       — rule is provider-api (AIM-103: shared with company-built
                 apps): blocked only after IT/Security confirm no app
                 dependency. Reported as "would block pending review".
  not-covered  — flagged traffic that maps to NO rule in endpoints.json
                 (detection gap, e.g. a tool seen by an endpoint collector
                 that has no network rule): the blocklist would NOT have
                 stopped it. Tracked so we don't overstate blocklist value.

Privacy: aggregates only. Distinct host_ref/user_ref COUNTS are reported;
no pseudonym values, no hostnames, no content ever leaves this script.

Input: JSONL events on stdin or via --input. Export from Postgres, e.g.:
  psql "$DATABASE_URL" -At -c \\
    "select json_agg(row_to_json(e)) from (
       select * from events where ts >= now() - interval '14 days') e" \\
    | python3 -c 'import json,sys; [print(json.dumps(r)) for r in json.load(sys.stdin)]' \\
    | python3 would_block_report.py --since 2026-07-08T00:00:00Z

Usage:
  python3 would_block_report.py --input events.jsonl
  python3 would_block_report.py --input events.jsonl --format json
"""

import argparse
import json
import os
import sys
from collections import defaultdict

DEFAULT_DETECTIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "endpoints.json")

# Detector family meaning "unapproved per endpoints.json". The current proxy
# collector emits policy:unapproved-tool (proxy_ingest.UNAPPROVED_DETECTOR);
# the canonical schema/guardrail policy and historical seeds use
# policy:unapproved-domain. Match the family, not one spelling.
UNAPPROVED_DETECTOR_PREFIX = "policy:unapproved-"
ENFORCE_CATEGORIES = {"api", "web", "telemetry", "gateway"}


def load_rules(path):
    with open(path, "r", encoding="utf-8") as f:
        db = json.load(f)
    by_provider = {}
    by_tool = {}
    for r in db["rules"]:
        if r.get("sanctioned"):
            continue
        by_provider.setdefault(r["provider"], r)
        if r.get("tool"):
            by_tool.setdefault(r["tool"], r)
    return db, by_provider, by_tool


def rule_for_event(ev, by_provider, by_tool):
    """Map an unapproved-flagged event back to its detection rule.
    Endpoint collectors know the tool exactly; the proxy collector stamps
    provider + tool_raw. Try tool_raw→rule.tool first (most specific),
    then provider."""
    tool_raw = ev.get("tool_raw")
    if tool_raw and tool_raw in by_tool:
        return by_tool[tool_raw]
    prov = ev.get("provider")
    if prov and prov in by_provider:
        return by_provider[prov]
    return None


def tier_of(rule):
    if rule is None:
        return "not-covered"
    return "enforce" if rule.get("category") in ENFORCE_CATEGORIES else "review"


def is_unapproved(ev):
    return any(str(f.get("detector", "")).startswith(UNAPPROVED_DETECTOR_PREFIX)
               for f in ev.get("match_flags") or [])


def parse_ts_day(ts):
    return (ts or "")[:10] or None


def build_report(events, db, by_provider, by_tool, since=None, until=None):
    flagged = [e for e in events if is_unapproved(e)]
    if since:
        flagged = [e for e in flagged if (e.get("ts") or "") >= since]
    if until:
        flagged = [e for e in flagged if (e.get("ts") or "") <= until]

    total_events = len(events)
    ts_all = sorted(e["ts"] for e in events if e.get("ts"))

    stats = {}  # (bucket_label, tier) -> aggregates
    def bucket(rule, ev):
        key = (rule["id"] if rule else f"unmatched:{ev.get('tool_raw') or ev.get('provider') or 'unknown'}",
               tier_of(rule))
        b = stats.setdefault(key, {
            "events": 0, "hosts": set(), "users": set(),
            "by_day": defaultdict(int), "by_class": defaultdict(int),
            "sources": defaultdict(int),
            "provider": (rule or {}).get("provider") or ev.get("provider"),
            "tool": (rule or {}).get("tool") or ev.get("tool_raw"),
            "first": None, "last": None,
        })
        b["events"] += 1
        if ev.get("host_ref"):
            b["hosts"].add(ev["host_ref"])
        if ev.get("user_pseudonym") or ev.get("user_ref"):
            b["users"].add(ev.get("user_pseudonym") or ev.get("user_ref"))
        day = parse_ts_day(ev.get("ts"))
        if day:
            b["by_day"][day] += 1
        b["by_class"][ev.get("traffic_class") or "unknown"] += 1
        b["sources"][ev.get("source") or "unknown"] += 1
        ts = ev.get("ts")
        if ts:
            b["first"] = ts if b["first"] is None else min(b["first"], ts)
            b["last"] = ts if b["last"] is None else max(b["last"], ts)

    for ev in flagged:
        bucket(rule_for_event(ev, by_provider, by_tool), ev)

    def serialize(b):
        return {
            "events": b["events"],
            "distinct_hosts": len(b["hosts"]),
            "distinct_users": len(b["users"]),
            "provider": b["provider"],
            "tool": b["tool"],
            "first_seen": b["first"],
            "last_seen": b["last"],
            "by_day": dict(sorted(b["by_day"].items())),
            "by_traffic_class": dict(sorted(b["by_class"].items())),
            "by_source": dict(sorted(b["sources"].items())),
        }

    buckets = [
        {"key": k[0], "tier": k[1], **serialize(b)}
        for k, b in sorted(stats.items(),
                           key=lambda kv: (kv[0][1], -kv[1]["events"]))
    ]
    totals = defaultdict(int)
    for b in buckets:
        totals[b["tier"]] += b["events"]

    return {
        "generator": "aim-would-block-report/1.0",
        "detection_db": {"version": db.get("version"),
                         "updated": db.get("updated")},
        "window": {
            "first_event": ts_all[0] if ts_all else None,
            "last_event": ts_all[-1] if ts_all else None,
            "since_filter": since,
            "until_filter": until,
        },
        "events_scanned": total_events,
        "unapproved_flagged": len(flagged),
        "would_block_enforce_tier": totals["enforce"],
        "would_block_review_tier": totals["review"],
        "not_covered_by_blocklist": totals["not-covered"],
        "buckets": buckets,
    }


def render_markdown(rep):
    L = []
    w = rep["window"]
    L.append("# Would-block report — corporate proxy blocklist (AIM-113)")
    L.append("")
    L.append(f"Window: `{w['first_event']}` → `{w['last_event']}`"
             + (f" (filtered ≥ {w['since_filter']})" if w.get("since_filter") else ""))
    L.append(f"Detection DB: endpoints.json v{rep['detection_db']['version']} "
             f"(updated {rep['detection_db']['updated']})")
    L.append("")
    L.append(f"- Events scanned: **{rep['events_scanned']}**")
    L.append(f"- Flagged `policy:unapproved-*`: **{rep['unapproved_flagged']}**")
    L.append(f"- Would have been blocked (enforce tier): "
             f"**{rep['would_block_enforce_tier']}**")
    L.append(f"- Would block pending IT/Security review (provider-api): "
             f"**{rep['would_block_review_tier']}**")
    L.append(f"- Flagged but NOT covered by the blocklist (detection gap): "
             f"**{rep['not_covered_by_blocklist']}**")
    L.append("")
    L.append("| rule | tier | events | hosts | users | first | last | source |")
    L.append("|---|---|---|---|---|---|---|---|")
    for b in rep["buckets"]:
        src = ",".join(f"{k}:{v}" for k, v in b["by_source"].items())
        L.append(f"| {b['key']} | {b['tier']} | {b['events']} "
                 f"| {b['distinct_hosts']} | {b['distinct_users']} "
                 f"| {(b['first_seen'] or '')[:10]} | {(b['last_seen'] or '')[:10]} "
                 f"| {src} |")
    L.append("")
    L.append("Aggregates only — distinct-host/user counts, no pseudonyms, "
             "hostnames, or content.")
    return "\n".join(L) + "\n"


def iter_events(fp):
    for line in fp:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            print(f"warning: skipping unparseable line: {line[:80]}…",
                  file=sys.stderr)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Would-block report for the AIM-113 proxy blocklist")
    p.add_argument("--input", default="-",
                   help="JSONL events file (default: stdin)")
    p.add_argument("--detections", default=DEFAULT_DETECTIONS,
                   help="endpoint detection DB (default: endpoints.json "
                        "next to this script)")
    p.add_argument("--since", help="only count flagged events with ts >= "
                                   "this RFC3339 string (lexicographic)")
    p.add_argument("--until", help="only count flagged events with ts <= "
                                   "this RFC3339 string")
    p.add_argument("--format", default="markdown",
                   choices=["markdown", "json"])
    p.add_argument("--output", help="output file (default: stdout)")
    args = p.parse_args(argv)

    db, by_provider, by_tool = load_rules(args.detections)
    in_f = sys.stdin if args.input == "-" else open(args.input, "r",
                                                    encoding="utf-8")
    try:
        events = list(iter_events(in_f))
    finally:
        if in_f is not sys.stdin:
            in_f.close()

    rep = build_report(events, db, by_provider, by_tool,
                       since=args.since, until=args.until)
    text = (json.dumps(rep, indent=2) + "\n") if args.format == "json" \
        else render_markdown(rep)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {args.output}: {rep['unapproved_flagged']} flagged, "
              f"{rep['would_block_enforce_tier']} would-block (enforce tier)",
              file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
