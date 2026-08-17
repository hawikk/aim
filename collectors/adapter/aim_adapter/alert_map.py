"""Map ai-usage-event match_flags onto security.alert/v1 metadata stubs.

Adapters never publish alerts themselves; this helper documents and exercises
the field mapping from the contract (docs/adapter-contract.md §2.3).
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any


def _finding_type(detector: str) -> str:
    # security.alert finding_type: a.b with underscores, not colons
    cleaned = detector.replace(":", ".").replace("-", "_").lower()
    parts = [p for p in cleaned.split(".") if p]
    if len(parts) == 1:
        parts = ["policy", parts[0]]
    return f"{parts[0]}.{parts[1]}"[:80]


def _severity(flag: dict[str, Any]) -> str:
    sev = (flag.get("severity") or "low").lower()
    if sev in ("critical", "high", "medium", "low", "info"):
        return sev
    return "low"


def flags_to_alert_stubs(
    event: dict[str, Any],
    *,
    producer_version: str = "0.1.0",
) -> list[dict[str, Any]]:
    """Return one security.alert/v1-shaped stub per match_flag (metadata only)."""
    stubs: list[dict[str, Any]] = []
    tool_label = event.get("tool_raw") or event.get("tool") or "unknown"
    host_ref = event.get("host_ref") or ""
    observed = event.get("ts") or ""
    event_id = event.get("event_id") or ""

    for flag in event.get("match_flags") or []:
        if not isinstance(flag, dict):
            continue
        detector = str(flag.get("detector") or "policy.unknown")
        finding = _finding_type(detector)
        severity = _severity(flag)
        # Map low→info for alert vocabulary when needed — keep low as low.
        dedupe_src = f"{finding}|{tool_label}|{host_ref}|{flag.get('fingerprint') or ''}"
        dedupe = hashlib.sha256(dedupe_src.encode()).hexdigest()[:32]
        alert_id = str(uuid.uuid4())
        # uuid4 shape is already correct; ensure version nibble if replaced
        stubs.append(
            {
                "schema_version": "1.1",
                "alert_id": alert_id,
                "dedupe_key": dedupe,
                "pillar": "ai_usage",
                "producer": {"name": "aim-adapter", "version": producer_version[:40]},
                "finding_type": finding,
                "title": f"{detector} on {tool_label}"[:200],
                "severity": severity if severity != "info" else "low",
                "severity_id": {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(
                    severity, 4
                ),
                "status": "open",
                "observed_at": observed,
                "first_seen_at": observed,
                "last_seen_at": observed,
                "resource": {
                    "kind": "device",
                    "id": host_ref[:128] if host_ref else "unknown",
                },
                "evidence": {
                    "source_event_id": event_id,
                    "summary": f"detector={detector}; tool={tool_label}",
                },
                "labels": {
                    "tool": str(tool_label)[:64],
                    "detector": detector[:64],
                },
            }
        )
    return stubs
