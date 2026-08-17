#!/usr/bin/env python3
"""Gate precision benchmark harness.

Runs every corpus case against the real scanners (gitleaks / semgrep /
checkov / trivy), scores precision / recall per gate, enforces published FP
budgets, and auto-reverts a gate that exceeds its budget to observe mode.

Usage:
    python services/gatehouse/benchmark/run.py [--markdown] [--json-report PATH]
        [--write-modes] [--scorecard PATH] [--gates gitleaks,semgrep]

Exit codes:
    0  all budgets met
    1  precision/recall regression or FP budget breach
    2  setup error (no cases, missing scanners when required)
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

BENCH_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH_DIR.parent / "src"))
sys.path.insert(0, str(BENCH_DIR.parent))  # so `benchmark` is importable as a pkg

from gatehouse.models import Finding  # noqa: E402
from gatehouse.scanners import REGISTRY  # noqa: E402

from benchmark import GATES  # noqa: E402
from benchmark.cases import (  # noqa: E402
    Case, all_cases, assert_corpus_meets_charter,
)
from benchmark.modes import (  # noqa: E402
    apply_budget_decisions, load_budgets, load_modes, write_modes,
)


def materialize(case: Case, root: Path) -> list[str]:
    paths: list[str] = []
    for rel, content in case.files.items():
        full = root / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content)
        paths.append(rel.replace("\\", "/"))
    return paths


def available_scanners() -> list[str]:
    return [name for name in GATES if shutil.which(name)]


def run_case(case: Case, *, enabled: list[str]) -> dict[str, Any]:
    """Run enabled scanners on one case; return scoring row."""
    with tempfile.TemporaryDirectory(prefix="gate-precision-") as tmp:
        root = Path(tmp) / "repo"
        root.mkdir()
        paths = materialize(case, root)
        findings: list[Finding] = []
        errors: list[str] = []
        # Only run the scanners relevant to this case (or all for clean/any).
        if case.gate == "any" or case.clean:
            scanners = list(enabled)
        else:
            scanners = [s for s in enabled if s == case.gate]
        for name in scanners:
            scan_fn = REGISTRY[name]
            outcome = scan_fn(str(root), paths)
            if outcome.error:
                errors.append(f"{name}: {outcome.error}")
            findings.extend(outcome.findings)

    matched: list[dict] = []
    misses: list[dict] = []
    used: set[int] = set()
    for exp in case.expected:
        hit_idx = next(
            (i for i, f in enumerate(findings)
             if i not in used and exp.matches(f)),
            None)
        if hit_idx is None:
            misses.append({
                "path": exp.path, "rule_id": exp.rule_id, "gate": exp.gate,
                "package": exp.package,
            })
        else:
            used.add(hit_idx)
            f = findings[hit_idx]
            matched.append({
                "path": f.path, "rule_id": f.rule_id, "gate": f.scanner,
                "line": f.line,
            })

    # Findings on clean cases are false positives. Findings on positive cases
    # that did not match a seed are "unexpected" diagnostics (not budget FPs).
    fps = []
    unexpected = []
    for i, f in enumerate(findings):
        if i in used:
            continue
        row = {"path": f.path, "rule_id": f.rule_id, "gate": f.scanner,
               "line": f.line, "title": f.title[:120]}
        if case.clean:
            fps.append(row)
        else:
            unexpected.append(row)

    return {
        "case": case.id,
        "gate_class": case.gate_class,
        "gate": case.gate,
        "clean": case.clean,
        "seeded": len(case.expected),
        "matched": len(matched),
        "misses": misses,
        "false_positives": fps,
        "unexpected": unexpected,
        "reported": len(findings),
        "errors": errors,
        "matched_detail": matched,
    }


def _safe_div(n: float, d: float, default: float = 1.0) -> float:
    return round(n / d, 4) if d else default


def aggregate(rows: list[dict], budgets: dict) -> dict[str, Any]:
    """Per-gate precision / recall / FP rate + overall."""
    per_gate: dict[str, dict[str, Any]] = {}
    for name in GATES:
        seeded = tp = fn = fp = 0
        clean_cases = clean_silent = 0
        unexpected = 0
        for r in rows:
            # Attribute seeded findings by expected gate.
            for m in r["matched_detail"]:
                if m["gate"] == name:
                    tp += 1
            for miss in r["misses"]:
                if miss["gate"] == name:
                    fn += 1
            for f in r["false_positives"]:
                if f["gate"] == name:
                    fp += 1
            for u in r["unexpected"]:
                if u["gate"] == name:
                    unexpected += 1
            # Clean cases that target this gate (or any).
            if r["clean"] and r["gate"] in (name, "any"):
                clean_cases += 1
                if not any(f["gate"] == name for f in r["false_positives"]):
                    # For gate=any, silence means no findings from this gate.
                    if r["gate"] == "any":
                        if not any(f["gate"] == name for f in r["false_positives"]):
                            clean_silent += 1
                    elif not r["false_positives"]:
                        clean_silent += 1
                    else:
                        # FPs from other gates don't dirty this gate's clean rate.
                        if not any(f["gate"] == name for f in r["false_positives"]):
                            clean_silent += 1

        seeded = tp + fn
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, seeded) if seeded else None
        # FP rate: fraction of clean controls that fired for this gate.
        gate_clean = [r for r in rows if r["clean"] and r["gate"] in (name, "any")]
        clean_n = len(gate_clean)
        dirty = sum(
            1 for r in gate_clean
            if any(f["gate"] == name for f in r["false_positives"]))
        fp_rate = _safe_div(dirty, clean_n, default=0.0) if clean_n else 0.0
        cfg = (budgets.get("gates") or {}).get(name) or {}
        per_gate[name] = {
            "seeded": seeded,
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "unexpected_on_positive": unexpected,
            "precision": precision if seeded or fp else 1.0,
            "recall": recall,
            "fp_rate": fp_rate,
            "clean_cases": clean_n,
            "clean_silent": clean_n - dirty,
            "clean_rate": _safe_div(clean_n - dirty, clean_n) if clean_n else 1.0,
            "budget": {
                "max_fp_rate": cfg.get("max_fp_rate"),
                "min_recall": cfg.get("min_recall"),
                "min_precision": cfg.get("min_precision"),
            },
        }

    total_tp = sum(g["true_positives"] for g in per_gate.values())
    total_fn = sum(g["false_negatives"] for g in per_gate.values())
    total_fp = sum(g["false_positives"] for g in per_gate.values())
    return {
        "per_gate": per_gate,
        "overall": {
            "true_positives": total_tp,
            "false_negatives": total_fn,
            "false_positives": total_fp,
            "precision": _safe_div(total_tp, total_tp + total_fp),
            "recall": _safe_div(total_tp, total_tp + total_fn),
        },
    }


def budgets_ok(per_gate: dict[str, dict], budgets: dict,
               *, only: list[str] | None = None) -> list[str]:
    failures = []
    for name, metrics in per_gate.items():
        if only is not None and name not in only:
            continue
        cfg = (budgets.get("gates") or {}).get(name) or {}
        # A gate with no seeded findings in this run has nothing to regress on.
        if metrics["seeded"] == 0:
            # Still fail if clean controls for this gate produced FPs.
            if metrics["clean_cases"] and metrics["fp_rate"] > float(cfg.get("max_fp_rate", 1)):
                failures.append(
                    f"{name}: fp_rate {metrics['fp_rate']:.4f} > max {cfg['max_fp_rate']}")
            continue
        if metrics["recall"] is not None and metrics["recall"] < float(cfg.get("min_recall", 0)):
            failures.append(
                f"{name}: recall {metrics['recall']:.4f} < min {cfg['min_recall']}")
        if metrics["precision"] < float(cfg.get("min_precision", 0)):
            failures.append(
                f"{name}: precision {metrics['precision']:.4f} < min {cfg['min_precision']}")
        if metrics["fp_rate"] > float(cfg.get("max_fp_rate", 1)):
            failures.append(
                f"{name}: fp_rate {metrics['fp_rate']:.4f} > max {cfg['max_fp_rate']}")
    return failures


def markdown_table(report: dict) -> str:
    lines = [
        f"# Gate precision benchmark (corpus v{report['corpus']['corpus_version']})",
        "",
        f"Seeded findings: **{report['corpus']['seeded_findings']}** · "
        f"cases: {report['corpus']['cases']} · "
        f"clean controls: {report['corpus']['clean_controls']}",
        "",
        "| Gate | Seeded | TP | FN | FP (clean) | Precision | Recall | FP rate | Mode |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    modes = report["modes"]["gates"]
    for name, m in report["aggregate"]["per_gate"].items():
        recall = f"{m['recall']:.2%}" if m["recall"] is not None else "n/a"
        lines.append(
            f"| {name} | {m['seeded']} | {m['true_positives']} | {m['false_negatives']} "
            f"| {m['false_positives']} | {m['precision']:.2%} | {recall} "
            f"| {m['fp_rate']:.2%} | {modes.get(name, '?')} |"
        )
    o = report["aggregate"]["overall"]
    lines += [
        "",
        f"**Overall precision: {o['precision']:.2%}** · "
        f"**overall recall: {o['recall']:.2%}**",
    ]
    if report.get("budget_failures"):
        lines += ["", "### Budget failures", ""]
        for f in report["budget_failures"]:
            lines.append(f"- {f}")
    if report["modes"].get("decisions"):
        lines += ["", "### Mode decisions", ""]
        for d in report["modes"]["decisions"]:
            lines.append(f"- `{d['gate']}` → **{d['mode']}**: {d['reason']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gates", default=",".join(GATES),
                        help="comma list of scanners to run")
    parser.add_argument("--require-scanners", action="store_true",
                        help="fail (exit 2) if any requested scanner binary is missing")
    parser.add_argument("--json-report", type=Path,
                        help="write full JSON report to this path")
    parser.add_argument("--scorecard", type=Path,
                        help="write scorecard dims 2+3 JSON to this path")
    parser.add_argument("--write-modes", action="store_true",
                        help="persist gate_modes.json after budget decisions")
    parser.add_argument("--modes-path", type=Path, default=None)
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--stats-only", action="store_true",
                        help="print corpus stats and exit (no scanners needed)")
    args = parser.parse_args(argv)

    cases = all_cases()
    try:
        stats = assert_corpus_meets_charter(cases)
    except AssertionError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2

    if args.stats_only:
        print(json.dumps(stats, indent=2))
        return 0

    requested = [g.strip() for g in args.gates.split(",") if g.strip()]
    for g in requested:
        if g not in GATES:
            print(json.dumps({"error": f"unknown gate: {g}"}))
            return 2
    present = available_scanners()
    enabled = [g for g in requested if g in present]
    missing = [g for g in requested if g not in present]
    if missing and args.require_scanners:
        print(json.dumps({"error": f"scanner(s) not installed: {', '.join(missing)}"}))
        return 2
    if not enabled:
        print(json.dumps({"error": "no scanner binaries available", "missing": missing}))
        return 2

    # Drop cases whose primary gate is unavailable (unless clean/any).
    runnable = [
        c for c in cases
        if c.clean or c.gate == "any" or c.gate in enabled
    ]
    rows = [run_case(c, enabled=enabled) for c in runnable]
    budgets = load_budgets()
    agg = aggregate(rows, budgets)
    failures = budgets_ok(agg["per_gate"], budgets, only=enabled)
    # Also fail if any scanner error on a positive case with zero findings.
    for r in rows:
        if r["errors"] and r["seeded"] and r["matched"] == 0:
            failures.append(f"case {r['case']}: scanner errors with zero matches: {r['errors']}")

    previous = load_modes(args.modes_path)
    # Only decide modes for scanners we actually ran — a partial --gates run
    # must not re-enforce a gate whose corpus half was skipped.
    measured = {
        name: metrics for name, metrics in agg["per_gate"].items()
        if name in enabled
    }
    modes, decisions = apply_budget_decisions(
        measured, budgets, previous=previous)
    # Preserve prior mode for gates we did not measure this run.
    for name in GATES:
        if name not in enabled:
            modes[name] = previous.get(name, "enforce")

    report = {
        "corpus": stats,
        "scanners_enabled": enabled,
        "scanners_missing": missing,
        "budgets": budgets,
        "aggregate": agg,
        "budget_failures": failures,
        "modes": {
            "gates": modes,
            "decisions": decisions,
        },
        "results": rows,
    }

    if args.write_modes:
        write_modes(
            modes, path=args.modes_path,
            source_report=str(args.json_report) if args.json_report else None,
            decisions=decisions)

    if args.markdown:
        print(markdown_table(report))
        print()
    print(json.dumps({
        "corpus": report["corpus"],
        "scanners_enabled": enabled,
        "scanners_missing": missing,
        "aggregate": report["aggregate"],
        "budget_failures": failures,
        "modes": report["modes"],
        # Keep full per-case detail out of stdout when huge; still in --json-report.
        "results_summary": [
            {k: r[k] for k in (
                "case", "gate_class", "gate", "clean", "seeded", "matched",
                "false_positives", "misses", "errors") if k in r}
            for r in rows
        ],
    }, indent=2))

    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(report, indent=2) + "\n")

    if args.scorecard:
        # Fix scorecard budget embedding
        sc = {
            "schema": "aim.gate-precision-scorecard/v1",
            "corpus_version": stats["corpus_version"],
            "dims": {
                "2_detection_precision": {
                    "label": "Detection precision (per-gate + overall)",
                    "overall_precision": agg["overall"]["precision"],
                    "overall_recall": agg["overall"]["recall"],
                    "per_gate": {
                        name: {
                            "precision": m["precision"],
                            "recall": m["recall"],
                            "fp_rate": m["fp_rate"],
                            "mode": modes.get(name),
                        }
                        for name, m in agg["per_gate"].items()
                    },
                },
                "3_enforcement_defensibility": {
                    "label": "Enforcement is backed by measured budgets",
                    "fp_budgets": {
                        name: (budgets.get("gates") or {}).get(name)
                        for name in GATES
                    },
                    "gates_in_observe": [
                        n for n, m in modes.items() if m == "observe"
                    ],
                    "budget_failures": failures,
                },
            },
            "summary_line": (
                f"precision={agg['overall']['precision']:.2%} "
                f"recall={agg['overall']['recall']:.2%} "
                f"on corpus v{stats['corpus_version']} "
                f"({stats['seeded_findings']} seeded findings)"
            ),
        }
        args.scorecard.parent.mkdir(parents=True, exist_ok=True)
        args.scorecard.write_text(json.dumps(sc, indent=2) + "\n")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
