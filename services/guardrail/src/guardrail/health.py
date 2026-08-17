"""Health endpoints for the poll-mode service (AIM-98).

The poller is a long-lived process with no other HTTP surface, so k8s
liveness/readiness probes need this minimal stdlib server. Semantics mirror
the ingest service (`services/ingest/src/server.ts`):

- `GET /healthz` — process is alive; always 200 {"status":"ok"}.
- `GET /readyz` — 200 {"status":"ok"} once a poll tick has succeeded within
  max(2x interval, 60s), else 503 {"status":"unavailable"}. Before the first
  successful tick it reports unavailable (fail-closed, same posture as the
  restricted-repo rule).
- `GET /lagz` — AIM-324: 200 {"status":"ok","destinations":[...]} with the
  per-destination delivery-lag report (pending/dead counts, oldest pending
  age) when a lag provider is wired (poll mode always wires one); 503 when
  the report cannot be computed, 404 when no provider is wired.

The server runs in a daemon thread so it never blocks or outlives the poll
loop, and it is best-effort: a bind failure is logged once and polling
continues without it (the poller's resilience principle takes precedence —
nothing probes it in the compose stack anyway).
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

DEFAULT_HEALTH_PORT = 8090
MIN_FRESHNESS_SECONDS = 60.0


def _log(payload: dict) -> None:
    print(json.dumps(payload), file=sys.stderr, flush=True)


def port_from_env(env: dict | None = None) -> int:
    """Read GUARDRAIL_HEALTH_PORT; default 8090."""
    env = env if env is not None else os.environ
    raw = env.get("GUARDRAIL_HEALTH_PORT")
    if raw is None or raw.strip() == "":
        return DEFAULT_HEALTH_PORT
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"GUARDRAIL_HEALTH_PORT must be a port number, got {raw!r}")
    if not 0 < value < 65536:
        raise ValueError(f"GUARDRAIL_HEALTH_PORT must be 1-65535, got {value}")
    return value


class HealthState:
    """Last-successful-tick record shared between the poll loop and the
    health handler. A single scalar written under the GIL is thread-safe
    enough for a probe; `now` is injectable for staleness tests."""

    def __init__(self, interval: float, *, now: Callable[[], float] = time.monotonic) -> None:
        self.last_success: float | None = None
        self.freshness_seconds = max(2 * interval, MIN_FRESHNESS_SECONDS)
        self._now = now

    def mark_success(self) -> None:
        self.last_success = self._now()

    def ready(self) -> bool:
        if self.last_success is None:
            return False  # fail-closed until the first tick succeeds
        return (self._now() - self.last_success) <= self.freshness_seconds


def make_handler(state: HealthState, lag_provider: Callable[[], list] | None = None) -> type[BaseHTTPRequestHandler]:
    """Build a request handler class bound to `state` (factored out so tests
    can exercise it without standing up a real socket).

    `lag_provider` (AIM-324) backs `GET /lagz`: a callable returning the
    per-destination delivery-lag report (see dbrunner.delivery_lag). Absent,
    /lagz answers 404 like any unknown path; a provider error answers 503 —
    a lag endpoint that cannot reach the database must look down, not stale."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._respond(200, {"status": "ok"})
            elif self.path == "/readyz":
                if state.ready():
                    self._respond(200, {"status": "ok"})
                else:
                    self._respond(503, {"status": "unavailable"})
            elif self.path == "/lagz" and lag_provider is not None:
                try:
                    self._respond(200, {"status": "ok", "destinations": lag_provider()})
                except Exception:  # noqa: BLE001 — report down, never stale
                    self._respond(503, {"status": "unavailable"})
            else:
                self._respond(404, {"error": "not found"})

        def _respond(self, code: int, body: dict) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *_args: object) -> None:
            pass  # silence the default stderr access log; ticks are logged already

    return Handler


def start_health_server(
    port: int,
    state: HealthState,
    lag_provider: Callable[[], list] | None = None,
) -> ThreadingHTTPServer | None:
    """Serve /healthz + /readyz (and /lagz when a lag provider is given) on
    0.0.0.0:`port` from a daemon thread.

    Best-effort: if the port cannot be bound, log once and return None — the
    poller keeps working without health endpoints.
    """
    try:
        server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(state, lag_provider))
    except OSError as exc:
        _log({
            "event": "guardrail.health.bind_error",
            "port": port,
            "error": str(exc),
        })
        return None
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="guardrail-health")
    thread.start()
    _log({"event": "guardrail.health.start", "port": server.server_address[1]})
    return server
