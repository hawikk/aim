"""`aim policy …` — control-plane policy operations.

Subcommands:
  simulate   dry-run a candidate policy against the last N days of historical
             findings / enforcement dispositions; report Δ blocks/alerts.

This is an *operator* surface (hits the control-plane API). It does not touch
local collector state. Auth: AIM_API_TOKEN (Bearer) or AIM_SESSION_COOKIE.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any


def _usage() -> str:
    return """usage: aim policy <subcommand> [options]

subcommands:
  simulate   dry-run candidate policy vs last N days of findings
             (reports Δ blocked / would_block / alerts)

environment:
  AIM_API_URL          control-plane base URL (required)
  AIM_API_TOKEN        admin service-token Bearer (or use --token)
  AIM_SESSION_COOKIE   alternative cookie auth

examples:
  aim policy simulate --days 7
  aim policy simulate --days 14 --pack-id pack-abc --json
  aim policy simulate --days 7 --disable-rule anomalous-volume-hourly
  aim policy simulate --days 7 --enforcement-file ./enforcement.json
"""


def cmd_policy(args: list[str]) -> int:
    if not args or args[0] in ("-h", "--help", "help"):
        sys.stdout.write(_usage())
        return 0 if args else 2
    sub, rest = args[0], args[1:]
    if sub == "simulate":
        return cmd_simulate(rest)
    sys.stderr.write(f"aim policy: unknown subcommand {sub!r}\n\n{_usage()}")
    return 2


def cmd_simulate(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="aim policy simulate",
        description="Dry-run a candidate policy against historical findings.",
    )
    p.add_argument("--days", type=int, default=7, help="lookback window (default 7, max 90)")
    p.add_argument("--pack-id", dest="pack_id", default=None, help="candidate signed pack id")
    p.add_argument("--pack-file", dest="pack_file", default=None, help="candidate pack envelope JSON")
    p.add_argument(
        "--enforcement-file",
        dest="enforcement_file",
        default=None,
        help="candidate endpoint enforcement.json",
    )
    p.add_argument(
        "--disable-rule",
        dest="disable_rules",
        action="append",
        default=[],
        help="drop a guardrail rule from the candidate (repeatable)",
    )
    p.add_argument(
        "--severity",
        dest="severities",
        action="append",
        default=[],
        metavar="RULE=LEVEL",
        help="override candidate severity (repeatable)",
    )
    p.add_argument("--json", action="store_true", help="print full report JSON")
    p.add_argument("--api-url", dest="api_url", default=None)
    p.add_argument("--token", dest="token", default=None)
    p.add_argument("--cookie", dest="cookie", default=None)
    ns = p.parse_args(argv)

    api_url = (ns.api_url or os.environ.get("AIM_API_URL") or "").rstrip("/")
    token = ns.token or os.environ.get("AIM_API_TOKEN") or ""
    cookie = ns.cookie or os.environ.get("AIM_SESSION_COOKIE") or ""
    if not api_url:
        sys.stderr.write("aim policy simulate: AIM_API_URL (or --api-url) is required\n")
        return 2
    if not token and not cookie:
        sys.stderr.write(
            "aim policy simulate: AIM_API_TOKEN/--token or AIM_SESSION_COOKIE/--cookie required\n"
        )
        return 2

    body: dict[str, Any] = {"days": ns.days}
    if ns.pack_id:
        body["packId"] = ns.pack_id
    if ns.pack_file:
        with open(ns.pack_file, encoding="utf-8") as fh:
            body["pack"] = json.load(fh)
    if ns.enforcement_file:
        with open(ns.enforcement_file, encoding="utf-8") as fh:
            body["enforcement"] = json.load(fh)
    if ns.disable_rules:
        body["disableRules"] = list(ns.disable_rules)
    if ns.severities:
        overrides: dict[str, str] = {}
        for item in ns.severities:
            if "=" not in item:
                sys.stderr.write(f"aim policy simulate: bad --severity {item!r} (want RULE=LEVEL)\n")
                return 2
            rid, level = item.split("=", 1)
            overrides[rid] = level
        body["severityOverrides"] = overrides

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie

    req = urllib.request.Request(
        f"{api_url}/api/policy/simulate",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
            report = json.loads(raw)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        sys.stderr.write(f"aim policy simulate: API {exc.code}: {detail[:500]}\n")
        return 1
    except urllib.error.URLError as exc:
        sys.stderr.write(f"aim policy simulate: request failed: {exc.reason}\n")
        return 1
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"aim policy simulate: bad JSON response: {exc}\n")
        return 1

    if ns.json:
        print(json.dumps(report, indent=2))
    else:
        summary = report.get("textSummary")
        if summary:
            print(summary)
        else:
            d = (report.get("delta") or {}).get("summary") or {}
            print(
                "aim policy simulate — dry-run\n"
                f"  Δ blocked={d.get('blocked')} would_block={d.get('would_block')} "
                f"alerts={d.get('alerts')} critical={d.get('criticalAlerts')}"
            )
    return 0
