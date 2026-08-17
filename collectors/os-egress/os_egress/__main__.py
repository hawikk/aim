"""CLI entry: python3 -m os_egress …"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .catalogue import load_endpoints, load_shadow_catalogue, match_rule, merge_rules
from .events import Pseudonymizer, parse_record, to_event
from .notice import NoticeNotAcknowledged, require_notice

_HERE = Path(__file__).resolve().parent
_DEFAULT_ENDPOINTS = _HERE.parent.parent / "proxy" / "endpoints.json"


def _sink_write(sink: str, path: str | None, events: list[dict]) -> None:
    if sink == "stdout":
        for ev in events:
            sys.stdout.write(json.dumps(ev, separators=(",", ":")) + "\n")
        return
    if sink == "file":
        if not path:
            raise SystemExit("--output is required with --sink file")
        with open(path, "a", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, separators=(",", ":")) + "\n")
        return
    raise SystemExit(f"unsupported sink: {sink}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="os_egress",
        description="AIM-321 OS egress metadata collector (AI SaaS domain presence).",
    )
    p.add_argument("--version", action="version", version=f"os_egress {__version__}")
    p.add_argument(
        "--input",
        "-i",
        default="-",
        help="JSONL file of DNS/flow records, or - for stdin",
    )
    p.add_argument(
        "--endpoints",
        default=str(_DEFAULT_ENDPOINTS),
        help="Path to endpoints.json catalogue (default: collectors/proxy/endpoints.json)",
    )
    p.add_argument(
        "--shadow-catalogue",
        default=None,
        help="Optional AIM-300 ai-tools.json to merge (discovery→coverage loop)",
    )
    p.add_argument("--sink", choices=("stdout", "file"), default="stdout")
    p.add_argument("--output", default=None, help="Path for --sink file")
    p.add_argument(
        "--require-notice",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enforce notice acknowledgment gate (default: true)",
    )
    args = p.parse_args(argv)

    if args.require_notice:
        try:
            require_notice()
        except NoticeNotAcknowledged as e:
            print(str(e), file=sys.stderr)
            return 2

    rules = load_endpoints(args.endpoints)
    if args.shadow_catalogue:
        rules = merge_rules(rules, load_shadow_catalogue(args.shadow_catalogue))

    pseudo = Pseudonymizer()
    events: list[dict] = []
    matched = 0
    skipped = 0

    def handle_line(line: str) -> None:
        nonlocal matched, skipped
        try:
            rec = parse_record(line)
        except json.JSONDecodeError:
            skipped += 1
            return
        if rec is None:
            skipped += 1
            return
        rule = match_rule(rules, rec["host"])
        if rule is None:
            skipped += 1
            return
        events.append(to_event(rec, rule, pseudo))
        matched += 1

    if args.input == "-":
        for line in sys.stdin:
            handle_line(line)
    else:
        with open(args.input, encoding="utf-8") as fh:
            for line in fh:
                handle_line(line)

    _sink_write(args.sink, args.output, events)
    print(
        f"os_egress: matched={matched} skipped={skipped} emitted={len(events)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
