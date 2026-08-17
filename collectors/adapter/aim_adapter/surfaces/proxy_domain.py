"""Surface: proxy / OS-egress domain observation.

Fidelity: PRESENCE only. Domain hits prove a tool/provider was contacted.
They do not yield model, tokens, or prompts. Be honest in dashboards.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
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


def _domains_for(manifest: dict[str, Any], surface: dict[str, Any]) -> list[str]:
    discovery = surface.get("discovery") or {}
    domains = [d.lower().rstrip(".") for d in (discovery.get("domains") or [])]
    return domains


def _host_matches(host: str, domains: list[str]) -> str | None:
    h = host.lower().rstrip(".")
    best = None
    best_len = -1
    for d in domains:
        if (h == d or h.endswith("." + d)) and len(d) > best_len:
            best = d
            best_len = len(d)
    return best


def discover(
    manifest: dict[str, Any],
    surface: dict[str, Any],
    *,
    root: str | None = None,
    host_hits: list[str] | None = None,
) -> DiscoveryResult:
    """Discovery from optional host_hits (tests / OS-egress feed).

    Without hits, present=False — proxy observation is runtime, not install-time.
    """
    tool_id = manifest["id"]
    domains = _domains_for(manifest, surface)
    hits = 0
    for host in host_hits or []:
        if _host_matches(host, domains):
            hits += 1
    present = hits > 0
    return DiscoveryResult(
        tool_id=tool_id,
        present=present,
        in_use=present,
        version=None,
        surface="proxy_domain",
        evidence=f"domain_hits={hits};domains={len(domains)}",
    )


def extract_rows(
    manifest: dict[str, Any],
    surface: dict[str, Any],
    *,
    root: str | None = None,
    records: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], int, list[str]]:
    """Each record: {host|dest_host, ts?, bytes_up?, bytes_down?, http_status?, device_id?}."""
    domains = _domains_for(manifest, surface)
    dropped = 0
    rows: list[dict[str, Any]] = []
    failures: list[str] = []

    for rec in records or []:
        if not isinstance(rec, dict):
            dropped += 1
            continue
        host = rec.get("host") or rec.get("dest_host") or rec.get("hostname")
        if not host or not isinstance(host, str):
            dropped += 1
            continue
        matched = _host_matches(host, domains)
        if not matched:
            # not this tool
            continue
        row = {
            "ts": rec.get("ts"),
            "session_id": rec.get("session_id") or f"proxy:{matched}:{rec.get('ts') or 'hit'}",
            "model": None,  # unobservable — presence only
            "provider": manifest.get("provider"),
            "bytes_up": rec.get("bytes_up"),
            "bytes_down": rec.get("bytes_down"),
            "http_status": rec.get("http_status"),
            "duration_ms": rec.get("duration_ms"),
            "traffic_class": rec.get("traffic_class") or "employee",
            "matched_domain": matched,
        }
        rows.append(row)
    return rows, dropped, failures


def load_catalogue_domains(
    endpoints_path: str | Path,
    rule_ids: list[str] | None = None,
) -> list[str]:
    """Optional helper: pull domains from collectors/proxy/endpoints.json by rule id."""
    data = json.loads(Path(endpoints_path).read_text(encoding="utf-8"))
    out: list[str] = []
    want = set(rule_ids or [])
    for rule in data.get("rules") or []:
        if want and rule.get("id") not in want:
            continue
        for d in rule.get("domains") or []:
            out.append(str(d).lower())
    return out
