"""Interval poller — runs evaluate-db unattended.

Wraps `dbrunner.run_dsn` in a sleep loop so the guardrail engine runs as a
compose service / post-ingest consumer without a manual command. In the
deployed topology the evaluator is a queue consumer triggered per batch; in
the local/compose stack this poller is the equivalent: it wakes on an interval
and drains every event not yet in `evaluated_events`.

Resilient by design: a poller must never die on a transient error. The most
common one is a startup race — the guardrail container comes up before the
ingest container has finished applying migrations, so `findings` /
`evaluated_events` don't exist yet. That (and a bounced Postgres) is logged and
retried on the next tick instead of crashing the loop.

Idempotent: every finding insert is `UNIQUE (rule_id, event_id) ON CONFLICT DO
NOTHING` and events are marked in `evaluated_events`, so overlapping or repeated
ticks never duplicate a finding.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Callable

from . import dbrunner, health

DEFAULT_INTERVAL_SECONDS = 15.0

# (D3.1 §5). Retention is enforced from the poller rather than a cron
# or a dedicated container: it is the one process already awake on an interval
# with the bus credential, and a retention rule enforced by a component that
# can be forgotten at deploy time is not enforced at all.
#
# Its own clock, not every tick: XTRIM MINID at the 15s poll interval would be
# ~5700 pointless calls a day against a 30-day window.
RETENTION_TRIM_INTERVAL_SECONDS = 6 * 3600


def _log(payload: dict) -> None:
    print(json.dumps(payload), file=sys.stderr, flush=True)


def interval_from_env(env: dict | None = None) -> float:
    """Read GUARDRAIL_POLL_INTERVAL (seconds); default 15s."""
    env = env if env is not None else os.environ
    raw = env.get("GUARDRAIL_POLL_INTERVAL")
    if raw is None or raw.strip() == "":
        return DEFAULT_INTERVAL_SECONDS
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"GUARDRAIL_POLL_INTERVAL must be a number of seconds, got {raw!r}")
    if value <= 0:
        raise ValueError(f"GUARDRAIL_POLL_INTERVAL must be > 0, got {value}")
    return value


def poll_once(dsn: str, rules_path: str, batch_size: int) -> dict:
    """Run one evaluate-db pass; return a structured tick summary."""
    started = time.perf_counter()
    summary = dbrunner.run_dsn(dsn, rules_path, batch_size=batch_size)
    return {
        "event": "guardrail.poll.tick",
        "events": summary.events,
        "findings": summary.findings,
        "findings_inserted": summary.findings_inserted,
        "batches": summary.batches,
        "wall_seconds": round(time.perf_counter() - started, 3),
    }


def trim_bus_retention(env: dict | None = None) -> dict | None:
    """Enforce the bus retention window; None when this install has no bus.

    Never raises. A retention trim that failed must not stop the guardrail
    poller from evaluating events — losing detection to keep a housekeeping
    job happy is the wrong trade. The failure is logged and retried on the
    next trim interval.
    """
    env = env if env is not None else os.environ
    if not env.get("ALERT_BUS_URL"):
        return None
    try:
        from . import bus

        client = bus._redis_client()
        return bus.trim_retention(client, stream_key=env.get("ALERT_BUS_STREAM") or bus.STREAM_KEY)
    except Exception as exc:  # noqa: BLE001 — housekeeping must not kill the loop
        _log({
            "event": "guardrail.bus.trim.error",
            "error_type": type(exc).__name__,
            "error": str(exc),
        })
        return None


def poll_forever(
    dsn: str,
    rules_path: str,
    interval: float,
    batch_size: int = dbrunner.DEFAULT_BATCH_SIZE,
    *,
    sleep: Callable[[float], None] = time.sleep,
    max_ticks: int | None = None,
    health_state: health.HealthState | None = None,
    now: Callable[[], float] = time.monotonic,
    trim: Callable[[], dict | None] = trim_bus_retention,
) -> int:
    """Poll every `interval` seconds until interrupted.

    `sleep`/`max_ticks`/`now`/`trim` are injection points for tests; in
    production the loop runs forever and is stopped by SIGTERM (see
    cli.cmd_poll). `health_state`, when given, is marked on every successful
    tick so /readyz can tell a live poller from a wedged one. Returns
    the number of ticks executed.
    """
    _log({
        "event": "guardrail.poll.start",
        "interval_seconds": interval,
        "rules": rules_path,
        "batch_size": batch_size,
    })
    ticks = 0
    # None means "trim on the first tick", so a stack restarted more often
    # than the trim interval still enforces retention rather than never
    # reaching its first trim.
    next_trim = None
    while max_ticks is None or ticks < max_ticks:
        try:
            _log(poll_once(dsn, rules_path, batch_size))
            if health_state is not None:
                health_state.mark_success()
        except Exception as exc:  # noqa: BLE001 — a poller must survive transient DB errors
            _log({
                "event": "guardrail.poll.error",
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
        tick_at = now()
        if next_trim is None or tick_at >= next_trim:
            try:
                trim()
            except Exception as exc:  # noqa: BLE001 — housekeeping must not stop the loop
                # trim_bus_retention swallows its own failures, but the guard
                # belongs here too: `trim` is injectable, and a housekeeping
                # call has no business being able to stop detection.
                _log({
                    "event": "guardrail.bus.trim.error",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                })
            # Scheduled from the tick time, not from after the trim: a slow
            # trim must not push its own next run further out each cycle.
            next_trim = tick_at + RETENTION_TRIM_INTERVAL_SECONDS
        ticks += 1
        if max_ticks is not None and ticks >= max_ticks:
            break
        sleep(interval)
    return ticks
