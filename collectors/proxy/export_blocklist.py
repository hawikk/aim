#!/usr/bin/env python3
"""Export unapproved AI-tool domains from the endpoint detection database
(endpoints.json) as a blocklist for the corporate proxy (AIM-113, phase 2b
of the inline-enforcement design, docs/inline-enforcement-design-2026-07.md).

We do NOT enforce anything ourselves: IT enforces the exported list on the
existing corporate proxy (Zscaler/Squid) under their acceptable-use
authority. Our contribution is the detection intelligence — the same
unapproved-domain knowledge the proxy collector (AIM-19) already uses to
flag traffic — plus the audit trail (would-block reporting, see
would_block_report.py).

Tiers (per design doc §Phase 2b + AIM-103 caveat):
  - enforce : unsanctioned rules in employee-tool categories (api, web,
              telemetry). These domains exist to serve the unapproved tool;
              blocking them is plain AUP enforcement.
  - review  : unsanctioned rules in the provider-api category (direct LLM
              APIs usable by BOTH employee tools and company-built
              applications, AIM-103). Blocking these at the proxy would also
              cut application traffic, so IT/Security must confirm no
              sanctioned app dependency before enforcement. Exported on
              request (--tier review / --tier all), never by default.

Safety invariant (hard error, refuses to export): no exported domain may
contain a sanctioned domain — blocking it would break Claude Code, Cursor,
or Kilo Code fleet-wide.

Domain matching semantics mirror endpoints.json: suffix-based, i.e. an
entry for "example.com" covers "example.com" and every "*.example.com".
The export header states this; IT maps it to the proxy's ACL idiom.

Output formats:
  domains : plain text, one domain per line (Zscaler custom URL category
            paste/upload, DNS RPZ source, generic)
  squid   : Squid dstdomain ACL file
  csv     : metadata-rich review sheet for IT/Security sign-off
            (domain, rule id, provider, tool, category, notes)
  json    : full manifest with per-rule detail + sha256 of the canonical
            domain list (change-tracking / audit)

Usage:
  python3 export_blocklist.py --format domains
  python3 export_blocklist.py --format squid --output blocklist-squid.conf
  python3 export_blocklist.py --format csv --tier all
  python3 export_blocklist.py --format json
"""

import argparse
import csv
import hashlib
import io
import json
import os
import sys

DEFAULT_DETECTIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "endpoints.json")

# Unsanctioned rules in these categories are safe to enforce at the proxy:
# the domains serve the unapproved employee tool itself.
ENFORCE_CATEGORIES = {"api", "web", "telemetry", "gateway"}
# Unsanctioned provider-api rules are review-tier (AIM-103: shared with
# company-built applications).
REVIEW_CATEGORIES = {"provider-api"}

TOOL_NAME = "aim-export-blocklist/1.0"


def load_db(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def select_rules(db, tier):
    """Partition unsanctioned rules by tier. Returns [(rule, tier), ...]
    sorted by rule id."""
    selected = []
    for r in db["rules"]:
        if r.get("sanctioned"):
            continue
        # Detection-only rules (AIM-321): still match for telemetry, but must
        # never enter a proxy blocklist export (e.g. parent domain of a
        # sanctioned API host under suffix matching).
        if r.get("blocklist_export") is False:
            continue
        cat = r.get("category") or ""
        if cat in ENFORCE_CATEGORIES:
            rule_tier = "enforce"
        elif cat in REVIEW_CATEGORIES:
            rule_tier = "review"
        else:
            # Unknown category on an unsanctioned rule: treat as review
            # rather than silently enforcing an unclassified thing.
            rule_tier = "review"
        if tier == "all" or tier == rule_tier:
            selected.append((r, rule_tier))
    return sorted(selected, key=lambda rt: rt[0]["id"])


def check_sanctioned_containment(db, selected):
    """Hard-fail if any exported domain would also match a sanctioned rule's
    domain under suffix semantics — blocking it would break approved tools."""
    sanctioned_domains = [
        d.lower()
        for r in db["rules"] if r.get("sanctioned")
        for d in r["domains"]
    ]
    violations = []
    for rule, _tier in selected:
        for d in rule["domains"]:
            d = d.lower()
            for sd in sanctioned_domains:
                if sd == d or sd.endswith("." + d):
                    violations.append(
                        f"{rule['id']}:{d} contains sanctioned domain {sd}")
    if violations:
        raise SystemExit(
            "REFUSING to export: blocklist domains would also block "
            "sanctioned tools:\n  " + "\n  ".join(violations))


def canonical_domains(selected):
    """Sorted, de-duplicated domain list (suffix overlaps within the export
    itself are harmless — proxies dedupe — but keep output canonical)."""
    doms = set()
    for rule, _tier in selected:
        doms.update(d.lower() for d in rule["domains"])
    return sorted(doms)


def manifest(db, selected, tier):
    doms = canonical_domains(selected)
    blob = "\n".join(doms).encode()
    return {
        "generator": TOOL_NAME,
        "source": {
            "file": "endpoints.json",
            "version": db.get("version"),
            "updated": db.get("updated"),
        },
        "tier": tier,
        "rule_count": len(selected),
        "domain_count": len(doms),
        "domains_sha256": hashlib.sha256(blob).hexdigest(),
        "matching": "suffix: an entry covers the domain and all subdomains",
        "rules": [
            {
                "id": r["id"],
                "provider": r["provider"],
                "tool": r.get("tool"),
                "category": r.get("category"),
                "tier": t,
                "domains": sorted(d.lower() for d in r["domains"]),
                **({"notes": r["notes"]} if r.get("notes") else {}),
            }
            for r, t in selected
        ],
    }


def header_lines(db, selected, tier, fmt):
    m = manifest(db, selected, tier)
    return [
        f"AI Monitoring blocklist export (AIM-113) — tier: {tier}",
        f"source: endpoints.json v{m['source']['version']} "
        f"updated {m['source']['updated']}",
        f"rules: {m['rule_count']}  domains: {m['domain_count']}  "
        f"sha256: {m['domains_sha256'][:16]}…",
        "matching: each entry covers the domain AND all its subdomains",
        "regenerate: python3 collectors/proxy/export_blocklist.py "
        f"--format {fmt} --tier {tier}",
    ]


def render_domains(db, selected, tier):
    out = ["# " + line for line in header_lines(db, selected, tier, "domains")]
    out += canonical_domains(selected)
    return "\n".join(out) + "\n"


def render_squid(db, selected, tier):
    out = ["# " + line for line in header_lines(db, selected, tier, "squid")]
    out.append("# usage: acl aim_unapproved_ai dstdomain \"/path/to/this/file\"")
    out.append("#        http_access deny aim_unapproved_ai")
    out += ["." + d for d in canonical_domains(selected)]
    return "\n".join(out) + "\n"


def render_csv(db, selected, tier):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["domain", "rule_id", "provider", "tool", "category",
                "tier", "notes"])
    for r, t in selected:
        for d in sorted(x.lower() for x in r["domains"]):
            w.writerow([d, r["id"], r["provider"], r.get("tool") or "",
                        r.get("category") or "", t, r.get("notes") or ""])
    return buf.getvalue()


def render_json(db, selected, tier):
    return json.dumps(manifest(db, selected, tier), indent=2) + "\n"


RENDERERS = {
    "domains": render_domains,
    "squid": render_squid,
    "csv": render_csv,
    "json": render_json,
}


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Export unapproved AI-tool domains as a corporate-proxy "
                    "blocklist (AIM-113)")
    p.add_argument("--format", required=True, choices=sorted(RENDERERS),
                   help="output format")
    p.add_argument("--tier", default="enforce",
                   choices=["enforce", "review", "all"],
                   help="enforce = employee-tool categories only (default); "
                        "review = provider-api rules needing IT/Security "
                        "confirmation (AIM-103); all = both")
    p.add_argument("--detections", default=DEFAULT_DETECTIONS,
                   help="endpoint detection DB (default: endpoints.json "
                        "next to this script)")
    p.add_argument("--output", help="output file (default: stdout)")
    args = p.parse_args(argv)

    db = load_db(args.detections)
    selected = select_rules(db, args.tier)
    if not selected:
        print(f"note: no unsanctioned rules in tier '{args.tier}'",
              file=sys.stderr)
    check_sanctioned_containment(db, selected)
    text = RENDERERS[args.format](db, selected, args.tier)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        m = manifest(db, selected, args.tier)
        print(f"wrote {args.output}: {m['domain_count']} domains, "
              f"{m['rule_count']} rules, tier={args.tier}, "
              f"sha256={m['domains_sha256'][:16]}…", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
