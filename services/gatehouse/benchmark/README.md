# Gate precision benchmark (AIM-334)

Measured FP/FN rates on a versioned corpus, per gate. This is the evidence that
makes [AIM-277](/AIM/issues/AIM-277) / [AIM-298](/AIM/issues/AIM-298) enforcement
defensible — leaders publish detection quality; we assert it.

## Charter

| Requirement | Where |
|---|---|
| ≥50 seeded findings across secret / SAST / IaC / SCA + clean controls | `cases.py` + `--stats-only` |
| Versioned corpus | `CORPUS_VERSION` in `__init__.py` |
| CI reports per-gate precision/recall; regressions block the gate's release | `run.py` in the acceptance job |
| Published FP budget per gate; breach → observe mode | `fp_budgets.json` + `modes.py` → `gate_modes.json` |
| Results feed the scorecard | `--scorecard` JSON (dims 2 + 3) |

## Run

```bash
# Corpus stats only (no scanners)
python services/gatehouse/benchmark/run.py --stats-only

# Full run inside the gatehouse image (real scanners)
docker run --rm -v "$PWD":/work:ro -w /work --user root \
  --entrypoint sh gatehouse:ci -c '
    pip install --quiet pytest
    python services/gatehouse/benchmark/run.py \
      --require-scanners --markdown \
      --json-report /tmp/precision-report.json \
      --scorecard /tmp/gate-precision-scorecard.json \
      --write-modes
  '
```

## Scoring

* **Recall** — of seeded expected findings, how many did the gate match?
* **Precision** — `TP / (TP + FP)` where FP are findings on *clean controls only*.
  Unexpected findings on positive cases are diagnostics (checkov often fires a
  cluster of secondary checks on one intentional misconfig) and do **not**
  count against the FP budget.
* **FP rate** — fraction of clean controls for that gate that produced any finding.

## Auto-observe

When a gate exceeds `max_fp_rate` or falls below `min_recall` / `min_precision`
in `fp_budgets.json`, the harness:

1. Fails CI (exit 1) — the gate's own release is blocked.
2. Writes `src/gatehouse/gate_modes.json` with that scanner set to `observe`.

`checkrun.blocks()` reads those modes: observe-mode findings still appear on
the check and the alert bus, but they cannot fail a merge until the corpus is
green again and the harness re-enforces.

Ops break-glass: `GATEHOUSE_FORCE_OBSERVE=gitleaks,semgrep`.
