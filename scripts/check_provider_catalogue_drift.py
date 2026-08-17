#!/usr/bin/env python3
"""Provider catalogue completeness + mirror drift guard (AIM-738).

Source of truth for App-LLM provider-api ids:
  collectors/proxy/endpoints.json  (rules where category == "provider-api")

Mirrors that MUST match that set (same membership; order free):
  apps/api/src/routes/dashboard.js   → PROVIDER_API_PROVIDERS
  services/guardrail/.../new_sources.py → DEFAULT_PROVIDERS

Also enforces:
  * endpoints.json is valid JSON (catches merge corruption like the AIM-595
    domain-expansion damage repaired under AIM-738)
  * every provider-api rule has at least one domain
  * optional self-test proves the rules fire

Usage:
  python3 scripts/check_provider_catalogue_drift.py            # human report
  python3 scripts/check_provider_catalogue_drift.py --check    # CI exit 1
  python3 scripts/check_provider_catalogue_drift.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENDPOINTS = ROOT / "collectors" / "proxy" / "endpoints.json"
DASHBOARD = ROOT / "apps" / "api" / "src" / "routes" / "dashboard.js"
NEW_SOURCES = (
    ROOT / "services" / "guardrail" / "src" / "guardrail" / "new_sources.py"
)
DOC = ROOT / "docs" / "app-llm-provider-catalogue.md"


def load_endpoints_providers(path: Path = ENDPOINTS) -> tuple[set[str], dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"FAIL: {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "rules" not in data:
        raise SystemExit(f"FAIL: {path} missing rules[]")
    providers: set[str] = set()
    empty_domain_rules: list[str] = []
    for i, rule in enumerate(data["rules"]):
        if not isinstance(rule, dict):
            raise SystemExit(f"FAIL: rules[{i}] is not an object")
        if rule.get("category") != "provider-api":
            continue
        prov = rule.get("provider")
        if not isinstance(prov, str) or not prov.strip():
            raise SystemExit(
                f"FAIL: provider-api rule {rule.get('id')!r} missing provider"
            )
        providers.add(prov.strip())
        domains = rule.get("domains") or []
        if not isinstance(domains, list) or not domains:
            empty_domain_rules.append(str(rule.get("id")))
    if empty_domain_rules:
        raise SystemExit(
            f"FAIL: provider-api rules with empty domains: {empty_domain_rules}"
        )
    if not providers:
        raise SystemExit("FAIL: no provider-api providers found in endpoints.json")
    return providers, data


def parse_js_provider_set(src: str) -> set[str]:
    m = re.search(
        r"const\s+PROVIDER_API_PROVIDERS\s*=\s*new\s+Set\(\[(?P<body>[\s\S]*?)\]\)",
        src,
    )
    if not m:
        raise SystemExit("FAIL: could not locate PROVIDER_API_PROVIDERS in dashboard.js")
    return set(re.findall(r"['\"]([a-z0-9_]+)['\"]", m.group("body")))


def parse_py_default_providers(src: str) -> set[str]:
    # Match from DEFAULT_PROVIDERS = ( through the closing ) that sits alone
    # on a line (comments may contain parentheses).
    m = re.search(
        r"DEFAULT_PROVIDERS\s*(?::\s*tuple\[[^\]]+\]\s*)?=\s*\(\s*(?P<body>[\s\S]*?)^\s*\)",
        src,
        re.M,
    )
    if not m:
        raise SystemExit("FAIL: could not locate DEFAULT_PROVIDERS in new_sources.py")
    return set(re.findall(r"['\"]([a-z0-9_]+)['\"]", m.group("body")))

def check() -> list[str]:
    errs: list[str] = []
    sot, meta = load_endpoints_providers()
    dash = parse_js_provider_set(DASHBOARD.read_text(encoding="utf-8"))
    ns = parse_py_default_providers(NEW_SOURCES.read_text(encoding="utf-8"))

    def diff(name: str, got: set[str]) -> None:
        missing = sorted(sot - got)
        extra = sorted(got - sot)
        if missing:
            errs.append(f"{name} missing providers {missing} (present in endpoints.json)")
        if extra:
            errs.append(f"{name} has extra providers {extra} (not in endpoints.json provider-api)")

    diff("dashboard.js PROVIDER_API_PROVIDERS", dash)
    diff("new_sources.DEFAULT_PROVIDERS", ns)

    if not DOC.is_file():
        errs.append(f"missing ownership doc {DOC.relative_to(ROOT)}")
    else:
        body = DOC.read_text(encoding="utf-8")
        for needle in ("Ownership", "provider-api", "endpoints.json", "AIM-738"):
            if needle not in body:
                errs.append(f"docs/app-llm-provider-catalogue.md missing section/mark '{needle}'")

    version = meta.get("version")
    if not isinstance(version, int):
        errs.append("endpoints.json version must be an integer")

    return errs


def report() -> int:
    sot, meta = load_endpoints_providers()
    print(f"endpoints.json version={meta.get('version')} updated={meta.get('updated')}")
    print(f"provider-api providers ({len(sot)}): {', '.join(sorted(sot))}")
    errs = check()
    if errs:
        print("DRIFT:")
        for e in errs:
            print(f"  - {e}")
        return 1
    print("OK: dashboard + new_sources mirrors match endpoints.json; ownership doc present")
    return 0


def self_test() -> int:
    """Prove the checker fails when a mirror drops a provider."""
    original = DASHBOARD.read_text(encoding="utf-8")
    try:
        # Drop one known provider from the JS set temporarily via a temp rewrite
        # of a copy — we mutate the real file briefly inside a try/finally.
        mutated = re.sub(
            r"\n\s*'openrouter',?",
            "\n",
            original,
            count=1,
        )
        if mutated == original:
            print("self-test could not mutate dashboard.js", file=sys.stderr)
            return 1
        DASHBOARD.write_text(mutated, encoding="utf-8")
        errs = check()
        if not any("PROVIDER_API_PROVIDERS" in e and "openrouter" in e for e in errs):
            print("self-test: expected openrouter missing error, got:", errs, file=sys.stderr)
            return 1
        print("self-test OK: checker fires when PROVIDER_API_PROVIDERS drifts")
        return 0
    finally:
        DASHBOARD.write_text(original, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="CI mode: exit 1 on drift")
    ap.add_argument("--self-test", action="store_true", help="prove rules fire")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    rc = report()
    if args.check:
        return rc
    return 0 if rc == 0 else 0  # human report still exits 0 unless --check


if __name__ == "__main__":
    sys.exit(main())
