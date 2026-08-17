"""Retention config for personal mode.

Personal mode holds exactly one data class — your own usage events — in a
local SQLite file. There is no findings or audit store here, so the prune only
enforces the events window. But it reads the SAME config surface and defaults
as the server-mode purger (services/ingest/src/retention.ts): the ordering
invariant is parsed and validated identically so a knob set for a fleet install
behaves the same on an individual one.

Defaults (keep in sync with services/ingest/src/retention.ts and
docs/privacy/data-minimization-and-pseudonymization.md):
    events   90 days
    findings 365 days   (validated, unused in personal mode)
    audit   730 days   (validated, unused in personal mode)

Invariant: audit >= findings >= events. Fail-closed: a bad config raises
RetentionConfigError and the caller SKIPS the prune (logs, deletes nothing)
rather than guessing a window.
"""

import os
from dataclasses import dataclass

DEFAULTS = {"events": 90, "findings": 365, "audit": 730}


class RetentionConfigError(ValueError):
    """Invalid retention config — caller must fail closed (skip prune)."""


@dataclass(frozen=True)
class RetentionConfig:
    events_days: int
    findings_days: int
    audit_days: int
    dry_run: bool


def _pos_int(env: dict, name: str, fallback: int) -> int:
    raw = env.get(name)
    if raw is None or str(raw).strip() == "":
        return fallback
    raw = str(raw).strip()
    try:
        n = int(raw)
    except ValueError:
        raise RetentionConfigError(f"invalid {name}: {raw!r} (expected a positive integer)")
    if str(n) != raw or n <= 0:
        raise RetentionConfigError(f"invalid {name}: {raw!r} (expected a positive integer)")
    return n


def _bool(env: dict, name: str) -> bool:
    return str(env.get(name, "")).strip().lower() in ("1", "true", "yes", "on")


def from_env(env: dict | None = None) -> RetentionConfig:
    """Parse + validate retention config. Raises RetentionConfigError on any
    parse error or ordering violation (fail-closed)."""
    env = env if env is not None else os.environ
    events = _pos_int(env, "RETENTION_EVENTS_DAYS", DEFAULTS["events"])
    findings = _pos_int(env, "RETENTION_FINDINGS_DAYS", DEFAULTS["findings"])
    audit = _pos_int(env, "RETENTION_AUDIT_DAYS", DEFAULTS["audit"])
    if not (audit >= findings >= events):
        raise RetentionConfigError(
            "retention windows must satisfy audit >= findings >= events "
            f"(got events={events}, findings={findings}, audit={audit})"
        )
    return RetentionConfig(
        events_days=events,
        findings_days=findings,
        audit_days=audit,
        dry_run=_bool(env, "RETENTION_DRY_RUN"),
    )
