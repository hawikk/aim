"""Process / binary observation source for coding-tool auto-discovery (AIM-644).

Endpoint agents (or a future process-inventory collector) can ship metadata-only
rows: binary basename + host pseudonym counts. No cmdline, no cwd, no content.

Sources:
- FixtureProcessSource: fixtures/process_observations.json for dev/test
- PostgresEventsProcessSource: optional aggregate over events.source='process'
  when that signal is stored (best-effort; empty when table/shape absent)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Protocol


@dataclass
class ProcessObservation:
    binary: str
    first_seen: datetime
    last_seen: datetime
    host_count: int
    event_count: int


class ProcessSource(Protocol):
    def fetch(self) -> Iterable[ProcessObservation]: ...


class FixtureProcessSource:
    def __init__(self, fixture_path: str):
        self.fixture_path = Path(fixture_path)

    def fetch(self) -> Iterable[ProcessObservation]:
        if not self.fixture_path.is_file():
            return
        raw = json.loads(self.fixture_path.read_text())
        for o in raw.get("observations", []):
            yield ProcessObservation(
                binary=o["binary"],
                first_seen=datetime.fromisoformat(
                    o["first_seen"].replace("Z", "+00:00")
                ),
                last_seen=datetime.fromisoformat(
                    o["last_seen"].replace("Z", "+00:00")
                ),
                host_count=int(o.get("host_count", 0)),
                event_count=int(o.get("event_count", 0)),
            )


class PostgresEventsProcessSource:
    """Best-effort process inventory from events where source='process'.

    No-op (empty) when the query fails — process signal is optional.
    """

    QUERY = """
        SELECT
            COALESCE(tool_raw, tool) AS binary,
            min(ts) AS first_seen,
            max(ts) AS last_seen,
            count(DISTINCT host_ref) AS host_count,
            count(*) AS event_count
        FROM events
        WHERE source = 'process'
        GROUP BY 1
    """

    def __init__(self, events_database_url: str):
        from sqlalchemy import create_engine

        self.engine = create_engine(events_database_url)

    def fetch(self) -> Iterable[ProcessObservation]:
        from sqlalchemy import text

        try:
            with self.engine.connect() as conn:
                for row in conn.execute(text(self.QUERY)):
                    yield ProcessObservation(
                        binary=row.binary,
                        first_seen=row.first_seen,
                        last_seen=row.last_seen,
                        host_count=row.host_count,
                        event_count=row.event_count,
                    )
        except Exception:
            return


class EmptyProcessSource:
    def fetch(self) -> Iterable[ProcessObservation]:
        return ()


def build_process_source(settings) -> ProcessSource:
    src = getattr(settings, "process_source", "fixture") or "fixture"
    if src == "none":
        return EmptyProcessSource()
    if src == "fixture":
        return FixtureProcessSource(settings.process_fixture_path)
    if src == "postgres":
        url = settings.events_database_url or settings.database_url
        return PostgresEventsProcessSource(url)
    raise ValueError(f"unknown SHADOW_AI_PROCESS_SOURCE: {src}")
