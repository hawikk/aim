#!/usr/bin/env python3
"""Generate the detector evasion capability statement (AIM-90, updated AIM-91,
extended AIM-102 into a standing adversarial program gate).

Runs every fixture in the adversarial corpus — the base fixtures
collectors/matcher-fixtures/evasion.json plus every file in
collectors/matcher-fixtures/adversarial/ — against each collector's endpoint
matcher module (verbatim copies of the unified ruleset
collectors/matcher-ruleset/matchers.py — this also exercises that the copies
are in sync), verifies that the pinned expectations still hold, and writes
docs/security/detector-evasion-capability.md.

Additionally (AIM-102):
  * --check also enforces the evasion-rate baseline
    (collectors/matcher-fixtures/evasion-baseline.json): CI fails if the
    per-rule caught/total evasion rate drops below the pinned baseline, even
    if someone edited fixtures to pin the weaker behavior. Updating the
    baseline is a deliberate, reviewed act (--update-baseline).
  * --json-report PATH writes a machine-readable report for CI artifacts /
    per-release publication.

Additionally (AIM-96):
  * Measured rates (baseline/evasion/FP-guard pass rates over the whole
    labeled corpus) are printed on every run — including --check, so CI logs
    publish them — and rendered into the doc with the attack-class × tool
    coverage matrix.

Usage:
    python3 scripts/matcher_evasion_report.py            # write the doc
    python3 scripts/matcher_evasion_report.py --check    # verify only (CI-safe)
    python3 scripts/matcher_evasion_report.py --update-baseline
    python3 scripts/matcher_evasion_report.py --check --json-report out.json

Exit code is non-zero if any fixture's expected behavior no longer matches
the actual matcher output (i.e. the doc would be a lie), or if the evasion
rate regressed against the baseline.
"""

import argparse
import datetime
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "collectors" / "matcher-fixtures" / "evasion.json"
ADVERSARIAL_DIR = ROOT / "collectors" / "matcher-fixtures" / "adversarial"
BASELINE = ROOT / "collectors" / "matcher-fixtures" / "evasion-baseline.json"
DOC = ROOT / "docs" / "security" / "detector-evasion-capability.md"

# ruleset -> matcher module path
MODULES = {
    "claude-code": "collectors/claude-code/aim_collector/matchers.py",
    "cursor": "collectors/cursor/cursor_collector/matchers.py",
    "kilo-code": "collectors/kilo-code/kilo_collector/matchers.py",
    "kimi-code": "collectors/kimi-code/kimi_collector/matchers.py",
}


def load_module(ruleset: str, path: str):
    spec = importlib.util.spec_from_file_location(f"matchers_{ruleset}", ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def corpus_paths() -> list[Path]:
    """Base fixtures first, then adversarial corpus files (sorted)."""
    paths = [FIXTURES]
    if ADVERSARIAL_DIR.is_dir():
        paths += sorted(ADVERSARIAL_DIR.glob("*.json"))
    return paths


def load_corpus():
    """Load and merge all corpus files. Returns the merged data dict."""
    merged = {"version": None, "categories": {}, "rulesets": {}, "cases": []}
    seen_ids: set[str] = set()
    for path in corpus_paths():
        data = json.loads(path.read_text(encoding="utf-8"))
        if merged["version"] is None:
            merged["version"] = data.get("version")
            merged["categories"] = data.get("categories", {})
        for ruleset, rules in data.get("rulesets", {}).items():
            merged["rulesets"].setdefault(ruleset, [])
            for rule in rules:
                if rule not in merged["rulesets"][ruleset]:
                    merged["rulesets"][ruleset].append(rule)
        for case in data.get("cases", []):
            if case["id"] in seen_ids:
                raise SystemExit(f"duplicate case id {case['id']!r} in corpus ({path})")
            seen_ids.add(case["id"])
            merged["cases"].append(case)
    return merged


def evaluate(data):
    """Return {ruleset: {case_id: (case, actual_flagged)}}, and a drift list."""
    results, drift = {}, []
    for ruleset, mod_path in MODULES.items():
        mod = load_module(ruleset, mod_path)
        rs_results = {}
        for case in data["cases"]:
            if ruleset not in case["rulesets"]:
                continue
            flagged = case["rule"] in mod.scan_text(case["input"])
            rs_results[case["id"]] = (case, flagged)
            expected = case["expect"] == "flag"
            if flagged != expected:
                drift.append((ruleset, case["id"], case["expect"], flagged))
        results[ruleset] = rs_results
    return results, drift


def evasion_stats(results):
    """Per-rule evasion caught/total, per ruleset: {ruleset: {rule: (caught, total)}}."""
    stats = {}
    for ruleset, rs in results.items():
        per_rule: dict[str, list[int]] = {}
        for case, flagged in rs.values():
            if case["category"] != "evasion":
                continue
            caught, total = per_rule.get(case["rule"], (0, 0))
            per_rule[case["rule"]] = [caught + (1 if flagged else 0), total + 1]
        stats[ruleset] = {r: tuple(v) for r, v in per_rule.items()}
    return stats


def corpus_metrics(results):
    """Measured rates over the whole labeled corpus, per ruleset (AIM-96).

    The corpus IS the labeled sample: baseline pass rate (recall on
    unobfuscated positives), evasion catch rate (recall under obfuscation),
    FP-guard pass rate (1 - false-positive rate on negative samples), and the
    count of live known false positives. Published in the capability doc and
    printed by --check so CI logs carry the numbers.
    """
    metrics = {}
    for ruleset, rs in results.items():
        def tally(cat, positive):
            cases = [(c, f) for c, f in rs.values() if c["category"] == cat]
            return sum(1 for _, f in cases if f == positive), len(cases)

        kfp = [(c, f) for c, f in rs.values() if c["category"] == "known-false-positive"]
        metrics[ruleset] = {
            "detectors": len({c["rule"] for c, _ in rs.values()}),
            "baseline": tally("baseline", True),
            "evasion": tally("evasion", True),
            "fp_guards": tally("false-positive", False),
            "known_fps": sum(1 for _, f in kfp if f),
        }
    return metrics


def _rate(pair):
    hits, total = pair
    pct = f"{100 * hits / total:.0f}%" if total else "n/a"
    return f"{hits}/{total} ({pct})"


def check_baseline(stats):
    """Compare current evasion rates against the pinned baseline.

    Returns (regressions, notes). A regression is a per-rule evasion catch
    RATE drop (caught/total, compared as exact rationals) in any ruleset, or
    a baseline rule with no corpus coverage left. New rules absent from the
    baseline are notes, not failures.
    """
    if not BASELINE.exists():
        return [], [f"no baseline at {BASELINE.relative_to(ROOT)} — run --update-baseline"]
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))["evasion"]
    regressions, notes = [], []
    covered = set()
    for ruleset, per_rule in sorted(stats.items()):
        for rule, (caught, total) in sorted(per_rule.items()):
            covered.add(rule)
            if rule not in baseline:
                notes.append(f"{rule}: not in baseline (new rule?) — consider --update-baseline")
                continue
            base = baseline[rule]
            if caught * base["total"] < base["caught"] * total:
                regressions.append(
                    f"{ruleset}: {rule} evasion catch rate regressed "
                    f"{base['caught']}/{base['total']} -> {caught}/{total}"
                )
    for rule in sorted(set(baseline) - covered):
        regressions.append(f"{rule}: in baseline but no evasion cases in the corpus anymore")
    return regressions, notes


def write_baseline(stats):
    """Pin the current evasion rates as the new baseline (deliberate act)."""
    # Rulesets are unified; assert they agree and pin the canonical numbers.
    canonical = None
    for ruleset, per_rule in sorted(stats.items()):
        if canonical is None:
            canonical = per_rule
        elif per_rule != canonical:
            raise SystemExit(f"ruleset {ruleset} disagrees with the others — refusing to baseline")
    payload = {
        "version": 1,
        "description": (
            "Pinned evasion catch-rate baseline (AIM-102). CI fails when a rule's "
            "caught/total evasion rate drops below these numbers. Regenerate ONLY as a "
            "deliberate, reviewed act: python3 scripts/matcher_evasion_report.py "
            "--update-baseline — a rate-lowering baseline update means accepted weaker "
            "detection and needs CEO/Security sign-off, like any detector change."
        ),
        "generated": datetime.date.today().isoformat(),
        "corpus": [str(p.relative_to(ROOT)) for p in corpus_paths()],
        "evasion": {r: {"caught": c, "total": t} for r, (c, t) in sorted(canonical.items())},
    }
    BASELINE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return BASELINE


def json_report(data, results, stats, regressions, notes):
    rules = {}
    for ruleset, per_rule in sorted(stats.items()):
        for rule, (caught, total) in sorted(per_rule.items()):
            entry = rules.setdefault(rule, {"evasion_caught": caught, "evasion_total": total,
                                            "per_ruleset": {}, "misses": []})
            entry["per_ruleset"][ruleset] = {"caught": caught, "total": total}
        for case, flagged in results[ruleset].values():
            if case["category"] == "evasion" and not flagged:
                if case["id"] not in rules[case["rule"]]["misses"]:
                    rules[case["rule"]]["misses"].append(case["id"])
    return {
        "generated": datetime.date.today().isoformat(),
        "corpus": [str(p.relative_to(ROOT)) for p in corpus_paths()],
        "cases_total": len(data["cases"]),
        "rules": rules,
        "baseline_regressions": regressions,
        "baseline_notes": notes,
    }


def render(data, results, metrics):
    today = datetime.date.today().isoformat()
    corpus_list = ", ".join(f"`{p.relative_to(ROOT)}`" for p in corpus_paths())
    lines = [
        "# Detector evasion capability statement",
        "",
        f"Generated by `scripts/matcher_evasion_report.py` from the adversarial corpus "
        f"({corpus_list}) on {today}. Do not edit by hand;",
        "edit the fixtures and re-run the script. Behavior shown here is enforced in CI by",
        "`collectors/*/tests/test_matcher_evasion.py`, by this script's `--check` mode, and",
        "by the evasion-rate baseline `collectors/matcher-fixtures/evasion-baseline.json`",
        "(AIM-102: CI fails if a rule's evasion catch rate drops below the pinned baseline).",
        "Program doc: `docs/security/adversarial-program.md`.",
        "",
        "This documents what the endpoint secret/PII/injection matchers actually catch",
        "and miss against common obfuscations, so the \"secret-in-prompt\" and",
        "\"injection-attempt\" controls' strength is stated honestly rather than assumed.",
        "",
        "Since AIM-91 all four collectors run one unified ruleset (canonical source:",
        "`collectors/matcher-ruleset/matchers.py`, synced into each collector package by",
        "`scripts/sync_matcher_ruleset.py` and verified in CI), so the per-ruleset tables",
        "below are identical by construction — they are rendered separately to prove the",
        "synced copies all behave the same.",
        "",
        "## Measured rates (whole labeled corpus, per ruleset)",
        "",
        "The fixture corpus is the labeled sample: **baseline** = recall on unobfuscated",
        "positives, **evasion caught** = recall under obfuscation, **FP guards** = 1 −",
        "false-positive rate on negative samples, **known FPs** = accepted, documented",
        "false positives that still fire.",
        "",
        "| Ruleset | Detectors | Baseline pass | Evasion caught | FP guards pass | Known FPs |",
        "|---|---|---|---|---|---|",
    ]
    for ruleset in MODULES:
        m = metrics[ruleset]
        lines.append(
            f"| `{ruleset}` | {m['detectors']} | {_rate(m['baseline'])} | "
            f"{_rate(m['evasion'])} | {_rate(m['fp_guards'])} | {m['known_fps']} |"
        )
    lines.append("")

    # Coverage matrix: attack class × tool (AIM-96 acceptance criterion).
    lines += [
        "## Coverage matrix (attack class × tool)",
        "",
        "Detector coverage is uniform across tools by construction (one synced",
        "ruleset); the matrix exists so a future per-tool divergence shows up as a",
        "hole here instead of in an incident review.",
        "",
        "| Attack class | Detector | " + " | ".join(f"`{r}`" for r in MODULES) + " |",
        "|---|---|" + "---|" * len(MODULES),
    ]
    all_rules = sorted({r for rules in data["rulesets"].values() for r in rules})
    by_class: dict[str, list[str]] = {}
    for rule in all_rules:
        by_class.setdefault(rule.split(":", 1)[0], []).append(rule)
    for cls in sorted(by_class):
        for rule in by_class[cls]:
            cells = " | ".join(
                "✓" if rule in data["rulesets"].get(rs, []) else "—" for rs in MODULES
            )
            lines.append(f"| {cls} | `{rule}` | {cells} |")
    lines.append("")

    for ruleset in MODULES:
        rs = results[ruleset]
        rules = data["rulesets"][ruleset]
        lines += [f"## Ruleset: `{ruleset}`", ""]
        lines += [
            "| Detector | Evasion caught | Evasion missed | FP guards pass | Known FPs |",
            "|---|---|---|---|---|",
        ]
        misses, known_fps = [], []
        for rule in rules:
            cases = [t for t in rs.values() if t[0]["rule"] == rule]
            ev = [(c, f) for c, f in cases if c["category"] == "evasion"]
            caught = sum(1 for _, f in ev if f)
            missed = sum(1 for _, f in ev if not f)
            fp = [(c, f) for c, f in cases if c["category"] == "false-positive"]
            fp_ok = sum(1 for _, f in fp if not f)
            kfp = [(c, f) for c, f in cases if c["category"] == "known-false-positive"]
            kfp_live = sum(1 for _, f in kfp if f)
            lines.append(
                f"| `{rule}` | {caught}/{len(ev)} | {missed}/{len(ev)} | "
                f"{fp_ok}/{len(fp)} | {kfp_live} |"
            )
            misses += [(c, f) for c, f in ev if not f]
            known_fps += [(c, f) for c, f in kfp if f]
        lines.append("")

        if misses:
            lines += ["### Measured evasion misses", ""]
            for case, _ in misses:
                lines.append(f"- `{case['id']}` ({case['rule']}): {case['note']}")
            lines.append("")
        if known_fps:
            lines += ["### Known false positives", ""]
            for case, _ in known_fps:
                lines.append(f"- `{case['id']}` ({case['rule']}): {case['note']}")
            lines.append("")

    lines += [
        "## Interpretation",
        "",
        "- One unified ruleset runs on every collector. Detection is multi-pass:",
        "  raw text; a Unicode-normalized pass (NFKC, confusable folding for",
        "  dash/quote/Cyrillic lookalikes, quote/backtick equivalence, `[at]`/`[dot]`",
        "  folding); a whitespace-deleted pass restricted to token-style detectors;",
        "  and a bounded base64 decode-and-rescan. The split/insertion, case-change,",
        "  Unicode-lookalike, and base64-wrap evasion classes measured in AIM-90 are",
        "  now caught — see the per-rule tables above.",
        "- AIM-96 added the third detector category: `injection:*` (prompt-injection",
        "  and jailbreak phrasings — instruction-override, persona/system-prompt",
        "  override, system-prompt extraction, jailbreak personas, chat-template",
        "  delimiter injection) in EN/DE/FR/ES; EU national-ID PII detectors (ES",
        "  DNI/NIE check letter, FR NIR mod-97 key, DE Steuer-ID ISO 7064 Mod 11,10,",
        "  IT codice fiscale structure-only); and new secret types (JWT with",
        "  header-decode validation, Google/Stripe/npm/PyPI/SendGrid keys, Slack",
        "  webhooks). Injection patterns are prose-class and deliberately tight",
        "  (qualified nouns, imperative constructions); they emit at medium",
        "  severity because defensive discussion of injection is constant in a",
        "  coding fleet — see the known-FP entries above.",
        "- Validated detectors keep precision high while broadening recall: Luhn",
        "  checksum for credit cards (catches Amex, rejects `4111 1111 1111 1112`),",
        "  MOD-97 for IBAN, structural area/group/serial checks for US SSN, and",
        "  repeated-char placeholder suppression for API tokens (`ghp_xxxx…`,",
        "  `sk-xxxx…` no longer flag).",
        "- Retained misses (listed above, when present) are explicit and justified.",
        "  The AIM-102 adversarial corpus added encoding-depth misses (hex, double",
        "  base64, MIME-wrapped base64, zero-width-space insertion, raw JSON `\\uXXXX`",
        "  escapes) and separator-substitution misses (dot-separated SSN, `(at)`/`(dot)`",
        "  email) — each is triaged in `docs/security/guardrail-adversarial-findings.md`",
        "  and closing any of them is a detector change needing CEO/Security sign-off.",
        "- Accepted known false positives (listed above, when present) — currently:",
        "  any structurally valid bare 9-digit run flags as SSN, which is the price",
        "  of catching separator-less SSN evasion. Tune downstream if noisy.",
        "",
        "## Maintenance",
        "",
        "1. Edit the canonical ruleset `collectors/matcher-ruleset/matchers.py` only.",
        "2. Run `python3 scripts/sync_matcher_ruleset.py` (CI verifies with `--check`).",
        "3. Update the corpus (`collectors/matcher-fixtures/evasion.json` and/or a file",
        "   in `collectors/matcher-fixtures/adversarial/`) and re-run this script.",
        "4. If the evasion catch rate changed intentionally, regenerate the baseline with",
        "   `--update-baseline` and get the same sign-off as a detector change.",
        "",
        "Detector behavior changes are security-relevant and need CEO/Security",
        "sign-off before implementation (the AIM-91 proposal was ratified on the",
        "issue thread). Refresh cadence for the corpus: `docs/security/adversarial-program.md`.",
        "",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify expectations + baseline, do not write the doc")
    ap.add_argument("--update-baseline", action="store_true", help="pin current evasion rates as the new baseline")
    ap.add_argument("--json-report", metavar="PATH", help="write a machine-readable report to PATH")
    args = ap.parse_args()

    data = load_corpus()
    results, drift = evaluate(data)
    stats = evasion_stats(results)
    metrics = corpus_metrics(results)
    regressions, notes = check_baseline(stats)

    if args.json_report:
        report = json_report(data, results, stats, regressions, notes)
        Path(args.json_report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.json_report}")

    if drift:
        print("DRIFT: pinned fixture expectations no longer match matcher behavior:")
        for ruleset, cid, expect, flagged in drift:
            print(f"  {ruleset}: {cid} expected {expect}, flagged={flagged}")
        print("Update the fixtures (if the behavior change is intended) or fix the matcher.")
        return 1

    # Deliberate re-pin must work even when the new rates are lower than the
    # previous baseline (honest residual expansion, e.g. AIM-730 monthly close).
    # Drift above still blocks: we never pin a baseline that disagrees with
    # fixture expect values.
    if args.update_baseline:
        if regressions:
            print("NOTE: re-pinning baseline over the following rate changes:")
            for line in regressions:
                print(f"  {line}")
        path = write_baseline(stats)
        print(f"wrote {path}")
        return 0

    if regressions:
        print("EVASION RATE REGRESSION against baseline:")
        for line in regressions:
            print(f"  {line}")
        print("If the weaker rate is intended, regenerate the baseline with --update-baseline")
        print("(a reviewed, sign-off-requiring act) — otherwise fix the matcher.")
        return 1

    for note in notes:
        print(f"note: {note}")

    for ruleset in MODULES:
        m = metrics[ruleset]
        print(f"rates [{ruleset}]: {m['detectors']} detectors, "
              f"baseline {_rate(m['baseline'])}, evasion caught {_rate(m['evasion'])}, "
              f"FP guards {_rate(m['fp_guards'])}, known FPs {m['known_fps']}")

    # AIM-579: overall corpus floors (in addition to per-rule baseline).
    OVERALL_FLOORS = {
        "baseline": 1.0,   # 100%
        "evasion": 0.90,   # AIM-578 target / AIM-579 floor
        "fp_guards": 1.0,  # 100%
    }
    floor_failures = []
    for ruleset in MODULES:
        m = metrics[ruleset]
        for key, floor in OVERALL_FLOORS.items():
            hits, total = m[key]
            rate = (hits / total) if total else 0.0
            if rate + 1e-12 < floor:
                floor_failures.append(
                    f"{ruleset}: {key} {hits}/{total} ({rate:.1%}) < floor {floor:.0%}"
                )
    if floor_failures:
        print("OVERALL CORPUS FLOOR FAILURE (AIM-579):")
        for line in floor_failures:
            print(f"  {line}")
        return 1

    if args.check:
        print("all fixture expectations match current matcher behavior; "
              "evasion rates hold baseline; overall floors (baseline 100 / "
              "evasion ≥90 / FP 100) pass")
        return 0

    DOC.write_text(render(data, results, metrics), encoding="utf-8")
    print(f"wrote {DOC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
