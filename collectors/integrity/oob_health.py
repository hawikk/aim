"""Out-of-band health signal independent of the agent process (AIM-639 / AIM-752).

The coding agent (and even the per-user collector hook process) must not be
able to silence liveness by killing their own tree. The OOB signal is a
host-level heartbeat file written by a root/SYSTEM-owned timer unit
(``aim-collector-oob-health.timer``) that:

1. Touches ``/var/lib/aim/oob-health.mtime`` (or ``AIM_OOB_HEALTH_FILE``)
2. Optionally POSTs ``/v1/heartbeat`` with ``source: "oob_systemd"`` using the
   device token under ``/etc/aim-collector/`` (root-readable)

An agent running as the engineer cannot stop the systemd unit without root,
and cannot rewrite the root-owned health file without privilege escalation.
Staleness is observed by the fleet coverage path and by
``scripts/independence_attestation.py``.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

OOB_HEARTBEAT_DEFAULT = "/var/lib/aim/oob-health.mtime"
OOB_HEARTBEAT_META_DEFAULT = "/var/lib/aim/oob-health.json"
# Default max age: 3 × 5 min timer + 60s slack (mirrors fleet dead threshold).
DEFAULT_STALE_SEC = 3 * 300 + 60


def health_path(env: dict[str, str] | None = None) -> Path:
    env = env if env is not None else os.environ
    return Path(env.get("AIM_OOB_HEALTH_FILE") or OOB_HEARTBEAT_DEFAULT)


def meta_path(env: dict[str, str] | None = None) -> Path:
    env = env if env is not None else os.environ
    return Path(env.get("AIM_OOB_HEALTH_META") or OOB_HEARTBEAT_META_DEFAULT)


@dataclass
class OOBHeartbeat:
    ts: float
    source: str = "oob_systemd"
    host_id: str | None = None
    collector_version: str | None = None
    pid: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def write_oob_heartbeat(
    *,
    path: Path | str | None = None,
    meta: Path | str | None = None,
    host_id: str | None = None,
    collector_version: str | None = None,
    source: str = "oob_systemd",
    now: float | None = None,
    env: dict[str, str] | None = None,
) -> OOBHeartbeat:
    """Write the OOB health signal. Safe to call from a root timer or tests."""
    env = env if env is not None else os.environ
    ts = float(now if now is not None else time.time())
    hb = OOBHeartbeat(
        ts=ts,
        source=source,
        host_id=host_id,
        collector_version=collector_version,
        pid=os.getpid(),
    )
    p = Path(path) if path is not None else health_path(env)
    m = Path(meta) if meta is not None else meta_path(env)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Atomic-ish: write then replace where possible
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(f"{ts}\n", encoding="utf-8")
    tmp.replace(p)
    try:
        m.parent.mkdir(parents=True, exist_ok=True)
        mtmp = m.with_suffix(m.suffix + ".tmp")
        mtmp.write_text(json.dumps(hb.to_dict(), sort_keys=True) + "\n", encoding="utf-8")
        mtmp.replace(m)
    except OSError:
        pass
    return hb


def read_oob_ts(path: Path | str | None = None, env: dict[str, str] | None = None) -> float | None:
    env = env if env is not None else os.environ
    p = Path(path) if path is not None else health_path(env)
    try:
        text = p.read_text(encoding="utf-8").strip().splitlines()[0]
        return float(text)
    except (OSError, IndexError, ValueError):
        try:
            return p.stat().st_mtime
        except OSError:
            return None


def oob_heartbeat_stale(
    *,
    path: Path | str | None = None,
    max_age_sec: float = DEFAULT_STALE_SEC,
    now: float | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, float | None]:
    """Return ``(is_stale_or_missing, age_sec_or_None)``."""
    ts = read_oob_ts(path, env=env)
    if ts is None:
        return True, None
    now_f = float(now if now is not None else time.time())
    age = max(0.0, now_f - ts)
    return age > max_age_sec, age
