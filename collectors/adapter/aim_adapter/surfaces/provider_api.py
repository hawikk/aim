"""Surface: provider API / OTel GenAI instrumentation.

Depth for first-party apps (service name, model, tokens). Employee coding
tools rarely expose this; reserved for genai_app-class traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DiscoveryResult:
    tool_id: str
    present: bool
    in_use: bool
    version: str | None
    surface: str
    evidence: str
    error: str | None = None
    paths: list[str] = field(default_factory=list)


def discover(
    manifest: dict[str, Any],
    surface: dict[str, Any],
    *,
    root: str | None = None,
    records: list[dict[str, Any]] | None = None,
) -> DiscoveryResult:
    n = len(records or [])
    return DiscoveryResult(
        tool_id=manifest["id"],
        present=n > 0,
        in_use=n > 0,
        version=None,
        surface="provider_api",
        evidence=f"otel_or_provider_records={n}",
    )


def extract_rows(
    manifest: dict[str, Any],
    surface: dict[str, Any],
    *,
    root: str | None = None,
    records: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], int, list[str]]:
    rows: list[dict[str, Any]] = []
    dropped = 0
    for rec in records or []:
        if not isinstance(rec, dict):
            dropped += 1
            continue
        if not rec.get("model") and not rec.get("service_name"):
            dropped += 1
            continue
        rows.append(
            {
                "ts": rec.get("ts"),
                "session_id": rec.get("session_id") or rec.get("trace_id") or "otel",
                "model": rec.get("model"),
                "provider": rec.get("provider") or manifest.get("provider"),
                "tokens_in": rec.get("tokens_in") or rec.get("input_tokens"),
                "tokens_out": rec.get("tokens_out") or rec.get("output_tokens"),
                "duration_ms": rec.get("duration_ms"),
            }
        )
    return rows, dropped, []
