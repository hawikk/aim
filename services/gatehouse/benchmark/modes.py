"""FP-budget decisions + gate_modes.json writer.

Runtime mode loading lives in ``gatehouse.modes`` (shipped in the image).
This module is the harness-side half: given measured per-gate metrics and the
published budgets, decide enforce vs observe and write both:

* ``services/gatehouse/benchmark/gate_modes.json`` (source of truth in repo)
* ``services/gatehouse/src/gatehouse/gate_modes.json`` (runtime copy the
  service reads)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import GATES

BENCH_DIR = Path(__file__).resolve().parent
BUDGETS_PATH = BENCH_DIR / "fp_budgets.json"
# Harness writes both so the runtime package stays in sync with the benchmark
# source of truth without a separate packaging step.
RUNTIME_MODES_PATH = BENCH_DIR.parent / "src" / "gatehouse" / "gate_modes.json"
BENCH_MODES_PATH = BENCH_DIR / "gate_modes.json"

VALID_MODES = frozenset({"enforce", "observe"})


def load_budgets(path: Path | None = None) -> dict[str, Any]:
    p = path or BUDGETS_PATH
    with open(p) as fh:
        return json.load(fh)


def default_modes() -> dict[str, str]:
    budgets = load_budgets()
    out = {}
    for name in GATES:
        cfg = (budgets.get("gates") or {}).get(name) or {}
        out[name] = cfg.get("default_mode", "enforce")
    return out


def load_modes(path: Path | None = None) -> dict[str, str]:
    """Read current modes from the runtime file (or a path override)."""
    modes = default_modes()
    p = path or RUNTIME_MODES_PATH
    if p.exists():
        try:
            data = json.loads(p.read_text())
            for name, mode in (data.get("gates") or {}).items():
                if name in GATES and mode in VALID_MODES:
                    modes[name] = mode
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    return modes


def apply_budget_decisions(
    per_gate: dict[str, dict[str, Any]],
    budgets: dict[str, Any] | None = None,
    *,
    previous: dict[str, str] | None = None,
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Derive modes from measured metrics + published budgets.

    Returns (modes, decisions) where each decision records why a gate flipped.
    """
    budgets = budgets or load_budgets()
    modes = dict(previous or default_modes())
    decisions: list[dict[str, Any]] = []
    for name in GATES:
        cfg = (budgets.get("gates") or {}).get(name) or {}
        metrics = per_gate.get(name) or {}
        max_fp = float(cfg.get("max_fp_rate", 0.1))
        min_recall = float(cfg.get("min_recall", 0.0))
        min_precision = float(cfg.get("min_precision", 0.0))
        fp_rate = metrics.get("fp_rate")
        recall = metrics.get("recall")
        precision = metrics.get("precision")
        # Gates with no seeded findings in this run keep their prior mode.
        if metrics.get("seeded", 0) == 0 and metrics.get("clean_cases", 0) == 0:
            continue
        breach = []
        if fp_rate is not None and fp_rate > max_fp:
            breach.append(f"fp_rate {fp_rate:.4f} > max {max_fp:.4f}")
        if recall is not None and recall < min_recall:
            breach.append(f"recall {recall:.4f} < min {min_recall:.4f}")
        if precision is not None and precision < min_precision:
            breach.append(f"precision {precision:.4f} < min {min_precision:.4f}")
        if breach:
            modes[name] = "observe"
            decisions.append({
                "gate": name, "mode": "observe", "reason": "; ".join(breach),
            })
        else:
            modes[name] = cfg.get("default_mode", "enforce")
            if previous and previous.get(name) == "observe":
                decisions.append({
                    "gate": name, "mode": "enforce",
                    "reason": "within budget — re-enforced",
                })
    return modes, decisions


def write_modes(
    modes: dict[str, str],
    *,
    path: Path | None = None,
    source_report: str | None = None,
    decisions: list[dict[str, Any]] | None = None,
) -> list[Path]:
    """Write modes to the runtime path (and the benchmark mirror)."""
    payload = {
        "version": 1,
        "description": (
            "Runtime mode per gate. enforce = findings may fail the check; "
            "observe = report only. Auto-written by the precision harness when "
            "a gate exceeds its FP budget."
        ),
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_report": source_report,
        "decisions": decisions or [],
        "gates": {name: modes.get(name, "enforce") for name in GATES},
    }
    text = json.dumps(payload, indent=2) + "\n"
    targets = []
    primary = path or RUNTIME_MODES_PATH
    for p in {primary, BENCH_MODES_PATH}:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        targets.append(p)
    return targets
