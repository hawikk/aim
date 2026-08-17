#!/usr/bin/env python3
"""Validate policies/mcp/threat-catalogue.yaml shape.

Stdlib + PyYAML only. Exit 0 on success, 1 on structural failure.

Also enforces continuous-update hygiene:
  - last_reviewed present (ISO date string)
  - allowlist_recommendations maps into deny/review suggestions
  - each threat cites detector_or_rail
  - curated never-approve lists are non-empty
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parents[1]
CAT = ROOT / "policies" / "mcp" / "threat-catalogue.yaml"
REQUIRED_THREAT = {"id", "title", "severity", "description", "detector_or_rail"}
SEVERITIES = {"low", "medium", "high", "critical"}
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _check_substring_list(items, path: str) -> list[str]:
    errs: list[str] = []
    if not isinstance(items, list):
        return [f"{path} must be a list"]
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            errs.append(f"{path}[{i}] must be a mapping")
            continue
        sub = item.get("substring")
        if not isinstance(sub, str) or not sub.strip() or len(sub) > 64:
            errs.append(f"{path}[{i}].substring must be a non-empty string <=64")
        reason = item.get("reason")
        if reason is not None and (not isinstance(reason, str) or len(reason) > 500):
            errs.append(f"{path}[{i}].reason must be a string <=500 when set")
    return errs


def main() -> int:
    data = yaml.safe_load(CAT.read_text())
    if not isinstance(data, dict):
        print("catalogue root must be a mapping", file=sys.stderr)
        return 1
    for k in ("version", "last_reviewed", "threats"):
        if k not in data:
            print(f"missing top-level key: {k}", file=sys.stderr)
            return 1
    if not isinstance(data["last_reviewed"], str) or not ISO_DATE.match(data["last_reviewed"]):
        print("last_reviewed must be YYYY-MM-DD", file=sys.stderr)
        return 1

    threats = data["threats"]
    if not isinstance(threats, list) or not threats:
        print("threats must be a non-empty list", file=sys.stderr)
        return 1
    ids: set[str] = set()
    for i, t in enumerate(threats):
        if not isinstance(t, dict):
            print(f"threats[{i}] not a mapping", file=sys.stderr)
            return 1
        missing = REQUIRED_THREAT - set(t)
        if missing:
            print(f"threats[{i}] missing {sorted(missing)}", file=sys.stderr)
            return 1
        if t["id"] in ids:
            print(f"duplicate threat id {t['id']!r}", file=sys.stderr)
            return 1
        ids.add(t["id"])
        if t["severity"] not in SEVERITIES:
            print(f"threats[{i}] bad severity {t['severity']!r}", file=sys.stderr)
            return 1
        # REQUIRED_THREAT already ensures key presence; still enforce non-empty string.
        rail = t.get("detector_or_rail")
        if not isinstance(rail, str) or not rail.strip():
            print(f"threats[{i}] detector_or_rail must be a non-empty string", file=sys.stderr)
            return 1

    # continuous update must map into allowlist recommendations.
    rec = data.get("allowlist_recommendations")
    if not isinstance(rec, dict):
        print("allowlist_recommendations must be a mapping", file=sys.stderr)
        return 1
    errs: list[str] = []
    for key in (
        "never_approve_server_substrings",
        "never_approve_tool_substrings",
    ):
        items = rec.get(key, [])
        errs.extend(_check_substring_list(items, key))
        if isinstance(items, list) and len(items) < 1:
            errs.append(f"{key} must contain at least one curated entry")

    nas = rec.get("never_approve_servers", [])
    if not isinstance(nas, list):
        errs.append("never_approve_servers must be a list")
    elif len(nas) < 1:
        errs.append("never_approve_servers must contain at least one curated entry")
    else:
        for i, item in enumerate(nas):
            if not isinstance(item, dict):
                errs.append(f"never_approve_servers[{i}] must be a mapping")
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip() or len(name) > 128:
                errs.append(f"never_approve_servers[{i}].name invalid")
            reason = item.get("reason")
            if reason is not None and (not isinstance(reason, str) or len(reason) > 500):
                errs.append(f"never_approve_servers[{i}].reason must be a string <=500 when set")

    seed = rec.get("pilot_seed_servers", [])
    if seed is not None and not isinstance(seed, list):
        errs.append("pilot_seed_servers must be a list")
    elif isinstance(seed, list):
        for i, s in enumerate(seed):
            if not isinstance(s, str) or not s.strip() or len(s) > 128:
                errs.append(f"pilot_seed_servers[{i}] must be a non-empty string <=128")

    for k in ("review_sla_days", "cve_response_business_days"):
        v = rec.get(k)
        if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 1):
            errs.append(f"{k} must be a positive int when set")

    cadence = data.get("update_cadence")
    if cadence is not None and (not isinstance(cadence, str) or not cadence.strip()):
        errs.append("update_cadence must be a non-empty string when set")

    if errs:
        for e in errs:
            print(e, file=sys.stderr)
        return 1

    print(
        f"OK {len(threats)} threats + allowlist_recommendations "
        f"in {CAT.relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
