"""Proxy corroboration signal: domain-level observations from stored events.

The proxy collector (collectors/proxy) already matched destination hostnames
against the detection DB at collection time and stored metadata-only events —
the hostname itself never crosses the wire. What we corroborate here is:
which detected-but-unsanctioned tools appeared, when, and from how many
distinct host pseudonyms.

Attribution honesty (AIM-300 acceptance criterion 3): proxy events are stored
UNATTRIBUTED by contract (AIM-58 — no OS identity at the network layer), so
proxy-sourced rows carry attributed=False and identity_count=None. We say so
explicitly instead of guessing.

Sources:
- PostgresEventsProxySource: read-only aggregate query over the ingest event
  store (prod).
- FixtureProxySource: dev/test JSON fixture with the same row shape.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Protocol


@dataclass
class ProxyObservation:
    tool_raw: str
    first_seen: datetime
    last_seen: datetime
    host_count: int
    event_count: int
    traffic_classes: list[str] = field(default_factory=list)


class ProxySource(Protocol):
    def fetch(self) -> Iterable[ProxyObservation]: ...


class FixtureProxySource:
    """Reads fixtures/proxy_observations.json: {"observations": [...]}."""

    def __init__(self, fixture_path: str):
        self.fixture_path = Path(fixture_path)

    def fetch(self) -> Iterable[ProxyObservation]:
        raw = json.loads(self.fixture_path.read_text())
        for o in raw.get("observations", []):
            yield ProxyObservation(
                tool_raw=o["tool_raw"],
                first_seen=datetime.fromisoformat(o["first_seen"].replace("Z", "+00:00")),
                last_seen=datetime.fromisoformat(o["last_seen"].replace("Z", "+00:00")),
                host_count=int(o.get("host_count", 0)),
                event_count=int(o.get("event_count", 0)),
                traffic_classes=list(o.get("traffic_classes", [])),
            )


class PostgresEventsProxySource:
    """Aggregates stored proxy events into per-tool observations.

    Read-only. Expects the ingest events table (migration 001+002): unsanctioned
    tools arrive as tool='other' with tool_raw set; sanctioned tools are
    excluded here because discovery is about what we did NOT onboard — the
    sanctioned estate is already visible in the main dashboards.
    """

    QUERY = """
        SELECT
            COALESCE(tool_raw, tool) AS tool_raw,
            min(ts) AS first_seen,
            max(ts) AS last_seen,
            count(DISTINCT host_ref) AS host_count,
            count(*) AS event_count,
            array_agg(DISTINCT traffic_class) FILTER (WHERE traffic_class IS NOT NULL) AS traffic_classes
        FROM events
        WHERE source = 'proxy'
          AND COALESCE(tool_raw, tool) NOT IN ('claude_code', 'cursor', 'kilo_code')
        GROUP BY 1
    """

    def __init__(self, events_database_url: str):
        from sqlalchemy import create_engine  # noqa: PLC0415

        self.engine = create_engine(events_database_url)

    def fetch(self) -> Iterable[ProxyObservation]:
        from sqlalchemy import text  # noqa: PLC0415

        with self.engine.connect() as conn:
            for row in conn.execute(text(self.QUERY)):
                yield ProxyObservation(
                    tool_raw=row.tool_raw,
                    first_seen=row.first_seen,
                    last_seen=row.last_seen,
                    host_count=row.host_count,
                    event_count=row.event_count,
                    traffic_classes=list(row.traffic_classes or []),
                )


def build_proxy_source(settings) -> ProxySource:
    if settings.proxy_source == "fixture":
        return FixtureProxySource(settings.proxy_fixture_path)
    if settings.proxy_source == "postgres":
        return PostgresEventsProxySource(settings.events_database_url)
    raise ValueError(f"unknown SHADOW_AI_PROXY_SOURCE: {settings.proxy_source}")
