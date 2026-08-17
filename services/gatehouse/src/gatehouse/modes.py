"""Per-scanner enforce/observe modes (AIM-334).

A gate whose measured precision falls below its published FP budget is auto-
reverted to **observe**: findings are still listed and published, but they do
not fail the check. Security re-enforces deliberately once the corpus is green.

Resolution order (later wins only for env overrides):

1. Default: every scanner is ``enforce``
2. On-disk ``gate_modes.json`` (next to this module, or ``GATEHOUSE_MODES_PATH``)
3. ``GATEHOUSE_GATE_MODES`` env (JSON object or ``gitleaks=observe,semgrep=enforce``)
4. ``GATEHOUSE_FORCE_OBSERVE`` env (comma list — ops break-glass)

The precision harness writes the on-disk file; this module only reads it.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

GATES = ("gitleaks", "semgrep", "checkov", "trivy")
VALID = frozenset({"enforce", "observe"})

_DEFAULT_PATH = Path(__file__).resolve().parent / "gate_modes.json"


def _parse_env_map(raw: str) -> dict[str, str]:
    raw = (raw or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return {k: str(v).lower() for k, v in data.items()
                if k in GATES and str(v).lower() in VALID}
    out: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            name, mode = part.split("=", 1)
            mode = mode.strip().lower()
        else:
            name, mode = part, "observe"
        name = name.strip()
        if name in GATES and mode in VALID:
            out[name] = mode
    return out


@lru_cache(maxsize=1)
def load_modes() -> dict[str, str]:
    """scanner -> enforce|observe. Cached for the process lifetime."""
    modes = {name: "enforce" for name in GATES}
    path = Path(os.environ.get("GATEHOUSE_MODES_PATH") or _DEFAULT_PATH)
    if path.exists():
        try:
            data = json.loads(path.read_text())
            for name, mode in (data.get("gates") or {}).items():
                if name in GATES and mode in VALID:
                    modes[name] = mode
        except (OSError, json.JSONDecodeError, TypeError, AttributeError):
            pass
    modes.update(_parse_env_map(os.environ.get("GATEHOUSE_GATE_MODES", "")))
    force = os.environ.get("GATEHOUSE_FORCE_OBSERVE", "")
    for name in force.split(","):
        name = name.strip()
        if name in GATES:
            modes[name] = "observe"
    return modes


def observe_scanners() -> set[str]:
    return {name for name, mode in load_modes().items() if mode == "observe"}


def clear_cache() -> None:
    """Test helper — drop the cached modes dict."""
    load_modes.cache_clear()
