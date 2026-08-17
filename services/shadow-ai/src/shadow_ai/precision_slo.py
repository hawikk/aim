"""Dark-tool / coverage alert false-positive precision SLO (AIM-626 / AIM-779).

Scope: **pageable** dark-tool alerts only (not the coverage ledger itself).
Ledger always shows dark tools; precision gates suppress noisy banners.

SLO (pilot):
  pageable_fp_rate ≤ 0.10 when analyst labels exist over a measurement window

  pageable_fp_rate = labeled_fp / (labeled_fp + labeled_tp)
  (unlabeled firings excluded from the rate; reported separately as unlabeled)

Inputs are pure records so unit tests do not need a live fleet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


SLO_TARGET_FP_RATE = 0.10
SLO_WINDOW_DAYS = 14


@dataclass(frozen=True)
class PageableAlertSample:
    """One pageable dark-tool alert observation in the measurement window."""

    tool_id: str
    fired: bool  # True if pageable banner fired; False if precision-suppressed
    suppress_reason: str | None = None
    # Analyst label after the fact (optional)
    label: str | None = None  # "fp" | "tp" | None


@dataclass(frozen=True)
class PrecisionSloReport:
    window_days: int
    target_fp_rate: float
    fired: int
    suppressed: int
    labeled_fp: int
    labeled_tp: int
    unlabeled_fired: int
    pageable_fp_rate: float | None  # None when no labels
    slo_met: bool | None  # None when insufficient labels
    notes: str

    def to_dict(self) -> dict:
        return {
            "window_days": self.window_days,
            "target_fp_rate": self.target_fp_rate,
            "fired": self.fired,
            "suppressed": self.suppressed,
            "labeled_fp": self.labeled_fp,
            "labeled_tp": self.labeled_tp,
            "unlabeled_fired": self.unlabeled_fired,
            "pageable_fp_rate": self.pageable_fp_rate,
            "slo_met": self.slo_met,
            "notes": self.notes,
        }


def measure_dark_tool_precision(
    samples: Iterable[PageableAlertSample],
    *,
    target_fp_rate: float = SLO_TARGET_FP_RATE,
    window_days: int = SLO_WINDOW_DAYS,
) -> PrecisionSloReport:
    fired = suppressed = labeled_fp = labeled_tp = unlabeled_fired = 0
    for s in samples:
        if s.fired:
            fired += 1
            if s.label == "fp":
                labeled_fp += 1
            elif s.label == "tp":
                labeled_tp += 1
            else:
                unlabeled_fired += 1
        else:
            suppressed += 1

    labeled = labeled_fp + labeled_tp
    if labeled == 0:
        return PrecisionSloReport(
            window_days=window_days,
            target_fp_rate=target_fp_rate,
            fired=fired,
            suppressed=suppressed,
            labeled_fp=0,
            labeled_tp=0,
            unlabeled_fired=unlabeled_fired,
            pageable_fp_rate=None,
            slo_met=None,
            notes=(
                "Insufficient labels: record analyst FP/TP on pageable dark-tool "
                f"alerts over a {window_days}-day window to evaluate the SLO."
            ),
        )

    rate = labeled_fp / labeled
    return PrecisionSloReport(
        window_days=window_days,
        target_fp_rate=target_fp_rate,
        fired=fired,
        suppressed=suppressed,
        labeled_fp=labeled_fp,
        labeled_tp=labeled_tp,
        unlabeled_fired=unlabeled_fired,
        pageable_fp_rate=round(rate, 4),
        slo_met=rate <= target_fp_rate,
        notes=(
            f"SLO target pageable_fp_rate ≤ {target_fp_rate:.0%} over {window_days}d. "
            "Suppressed candidates are precision gates (AIM-596), not ledger removals."
        ),
    )
