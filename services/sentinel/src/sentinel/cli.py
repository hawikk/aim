"""`sentinel` — serve, or answer questions about what it decided.

    sentinel serve                 run the loop (the compose entrypoint)
    sentinel once                  process the backlog and exit (CI, debugging)
    sentinel digest [--now]        send the medium/low rollup
    sentinel decisions [--incident ID | --alert ID]
                                   the audit trail: what it did and why
    sentinel incident ID parent incident + child finding links
    sentinel health                one JSON line, also served on :8091/healthz

``decisions`` is not a convenience. "Why did it page at 04:12" and "why did it
NOT page" are the questions asked after an incident, and they need an answer
that does not depend on log retention or on someone having tailed stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import telemetry
from .agent import Agent
from .bus import BusReader, ContractUnavailable
from .config import ConfigError, load
from .notify import Notifier
from .remediate import Catalogue, CatalogueUnavailable
from .store import Store
from .triage import Triager

HEALTH_PORT = 8091


def build_agent(args) -> Agent:
    telemetry.configure()
    cfg = load(args.config)
    store = Store(cfg.state_db)
    reader = BusReader(url=cfg.bus_url, stream_key=cfg.stream_key)
    return Agent(cfg=cfg, store=store, reader=reader, triager=Triager(cfg),
                 notifier=Notifier(cfg), catalogue=Catalogue.load())


def _health_server(agent: Agent) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") not in ("/healthz", "/health"):
                self.send_response(404)
                self.end_headers()
                return
            payload = json.dumps(agent.health()).encode()
            # 200 even when degraded: the container is alive and the body says
            # what is wrong. A 503 here would make compose restart the one
            # process that is trying to tell you the bus is down.
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("0.0.0.0", HEALTH_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def cmd_serve(args) -> int:
    agent = build_agent(args)
    _health_server(agent)
    channels = [c.name for c in agent.notifier.enabled_channels]
    print(f"sentinel {agent.cfg.stream_key} → channels={channels or '(none)'} "
          f"page_from={agent.cfg.page_from} "
          f"llm={'configured' if agent.cfg.llm.endpoint else 'not configured (pass-through)'}",
          flush=True)
    if not channels:
        # Not fatal — a stack with no channel still builds the audit trail and
        # the inbox — but it is the state where a human would learn nothing, so
        # it is said out loud at every start.
        print("sentinel WARNING: no notification channel is configured; pings will be "
              "recorded as undelivered in the outbox and nobody will be paged.", flush=True)
    agent.run_forever(log=lambda msg: print(msg, flush=True))
    return 0


def cmd_once(args) -> int:
    agent = build_agent(args)
    summary = agent.poll_once()
    print(json.dumps(summary, indent=2))
    return 0


def cmd_digest(args) -> int:
    agent = build_agent(args)
    result = agent.send_digest()
    print(json.dumps(result))
    return 0 if result["delivered"] or result["items"] == 0 else 1


def cmd_decisions(args) -> int:
    cfg = load(args.config)
    store = Store(cfg.state_db)
    rows = store.decisions(incident_id=args.incident, alert_id=args.alert, limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for row in rows:
        when = datetime.fromtimestamp(row["at"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        flag = f" [degraded: {row['degraded']}]" if row["degraded"] else ""
        print(f"{when}  {row['action'].upper():<18} {row['incident_id'] or '-'}{flag}")
        print(f"    why: {row['reason']}")
        print(f"    from alerts: {', '.join(row['alert_ids']) or '(none)'}")
        if row["triage"]:
            triage = row["triage"]
            print(f"    triage ({'llm' if row['llm_used'] else 'pass-through'}): "
                  f"{triage.get('is_real')} / {triage.get('confidence')} — {triage.get('why')}")
    return 0


def cmd_incident(args) -> int:
    """dump a parent incident and its child links."""
    cfg = load(args.config)
    store = Store(cfg.state_db)
    parent = store.get_parent_incident(args.incident_id)
    if parent is None:
        print(f"sentinel: no incident {args.incident_id!r}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(parent, indent=2, default=str))
        return 0
    print(f"incident {parent['incident_id']}")
    print(f"  correlation_key: {parent['correlation_key']}")
    print(f"  severity:        {parent['severity']}")
    print(f"  title:           {parent['title']}")
    print(f"  pillar/type:     {parent['pillar']} / {parent['finding_type']}")
    print(f"  alert_count:     {parent['alert_count']}")
    print(f"  children ({len(parent['children'])}):")
    for child in parent["children"]:
        tool = child.get("tool") or "-"
        user = (child.get("user_ref") or "-")[:12]
        print(f"    - {child['alert_id']}  tool={tool}  user={user}…  "
              f"resource={child['resource_ref'][:40]}  {child.get('source_uri') or ''}")
    return 0


def cmd_health(args) -> int:
    agent = build_agent(args)
    print(json.dumps(agent.health(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description=__doc__)
    parser.add_argument("--config", default=None, help="sentinel.yml (or $SENTINEL_CONFIG)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("serve").set_defaults(func=cmd_serve)
    sub.add_parser("once").set_defaults(func=cmd_once)
    sub.add_parser("digest").set_defaults(func=cmd_digest)
    sub.add_parser("health").set_defaults(func=cmd_health)

    decisions = sub.add_parser("decisions")
    decisions.add_argument("--incident")
    decisions.add_argument("--alert")
    decisions.add_argument("--limit", type=int, default=25)
    decisions.add_argument("--json", action="store_true")
    decisions.set_defaults(func=cmd_decisions)

    incident = sub.add_parser("incident",
                             help="show a parent incident and its child finding links")
    incident.add_argument("incident_id")
    incident.add_argument("--json", action="store_true")
    incident.set_defaults(func=cmd_incident)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, ContractUnavailable, CatalogueUnavailable) as err:
        # Startup-shaped failures get a plain message and a non-zero exit, not
        # a traceback: these are things an operator fixes in a file, and a
        # stack trace buries the one line that says which.
        print(f"sentinel: {err}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
