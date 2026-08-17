"""CLI: evaluate an NDJSON event stream against the policy ruleset.

Usage:
  python -m guardrail.cli evaluate --rules ../../policies/guardrail/v1 \
      --events events.ndjson --findings findings.ndjson --audit audit.ndjson
  cat events.ndjson | python -m guardrail.cli evaluate --rules ... --findings -
  python -m guardrail.cli validate-rules --rules ../../policies/guardrail/v1
  python -m guardrail.cli evaluate-db --rules ../../policies/guardrail/v1 # Postgres -> findings
  python -m guardrail.cli poll --rules ../../policies/guardrail/v1 # evaluate-db on an interval
  python -m guardrail.cli notify-test --email # send a synthetic test email
  python -m guardrail.cli notify-test --pagerduty # fire a synthetic PD test page

In the deployed topology this sits post-ingest on the event stream (queue
consumer); `--events -` (stdin) is the streaming path used for the pilot and
for local replay. `poll` is the unattended compose-service form: it
runs evaluate-db every GUARDRAIL_POLL_INTERVAL seconds.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from typing import Iterable, Iterator

from . import dbrunner, health, poller, telemetry
from .conditions import REPO_REF_SALT_ENV, repo_ref_for
from .engine import Engine
from .llm_judge import LlmJudge, LlmJudgeError
from .rules import RulesetError, load_ruleset

REQUIRED_EVENT_FIELDS = ("schema_version", "event_id", "ts", "host_ref", "tool", "session_id", "source", "match_flags")

# pilot demo set: realistic rule-flagged snippets for the LLM judge.
# The last one trips the mock provider's failure path so the pilot exercises
# error spans, not just the happy path.
LLM_JUDGE_DEMO_SNIPPETS = [
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "API_KEY = \"placeholder-do-not-commit\"",
    "password = hunter2  # TODO rotate before launch",
    "-----BEGIN OPENSSH PRIVATE KEY----- (redacted sample in docs)",
    "TRIGGER_ERROR simulated provider outage",
]


def _read_events(path: str) -> Iterator[dict]:
    fh = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
    try:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            missing = [f for f in REQUIRED_EVENT_FIELDS if f not in event]
            if missing:
                raise ValueError(f"line {lineno}: event missing required fields {missing}")
            yield event
    finally:
        if fh is not sys.stdin:
            fh.close()


def _open_out(path: str):
    return sys.stdout if path == "-" else open(path, "a", encoding="utf-8")


def cmd_evaluate(args: argparse.Namespace) -> int:
    ruleset = load_ruleset(args.rules)
    engine = Engine(ruleset)
    findings_out = _open_out(args.findings)
    audit_out = _open_out(args.audit) if args.audit else None

    n_events = n_findings = 0
    started = time.perf_counter()
    max_latency_ms = 0.0
    try:
        for event in _read_events(args.events):
            t0 = time.perf_counter()
            findings, audit = engine.evaluate(event)
            max_latency_ms = max(max_latency_ms, (time.perf_counter() - t0) * 1000)
            n_events += 1
            for f in findings:
                findings_out.write(json.dumps(f) + "\n")
                n_findings += 1
            if audit_out:
                for a in audit:
                    audit_out.write(json.dumps(a) + "\n")
        findings_out.flush()
        if audit_out:
            audit_out.flush()
    finally:
        for fh in (findings_out, audit_out):
            if fh is not None and fh is not sys.stdout:
                fh.close()

    elapsed = time.perf_counter() - started
    summary = {
        "events": n_events,
        "findings": n_findings,
        "rules": len(ruleset.rules),
        "ruleset_version": ruleset.version,
        "policy_hash": ruleset.content_hash,
        "wall_seconds": round(elapsed, 3),
        "max_eval_latency_ms_per_event": round(max_latency_ms, 3),
    }
    print(json.dumps(summary), file=sys.stderr)
    return 0


def cmd_evaluate_db(args: argparse.Namespace) -> int:
    """evaluate stored Postgres events, write findings rows.

    newly inserted findings are also pushed to the alert
    destinations from the ruleset's settings.alerts (or env when the policy
    defines none; off by default — see notify.py)."""
    started = time.perf_counter()
    summary = dbrunner.run_dsn(
        args.dsn or dbrunner.dsn_from_env(), args.rules, batch_size=args.batch_size
    )
    print(json.dumps({
        "events": summary.events,
        "findings": summary.findings,
        "findings_inserted": summary.findings_inserted,
        "batches": summary.batches,
        "wall_seconds": round(time.perf_counter() - started, 3),
    }), file=sys.stderr)
    return 0


def cmd_poll(args: argparse.Namespace) -> int:
    """run evaluate-db unattended on an interval (compose service).

    Alert delivery rides along: each tick forwards newly inserted
    findings to the env-configured destinations (off by default). Also serves
    /healthz + /readyz on GUARDRAIL_HEALTH_PORT for k8s probes and
    /lagz with the per-destination SIEM delivery-lag report."""
    dsn = args.dsn or dbrunner.dsn_from_env()
    interval = args.interval if args.interval is not None else poller.interval_from_env()

    # Poll mode is the only long-lived form, so the health server lives here.
    health_state = health.HealthState(interval)

    def lag_provider() -> list:
        """per-destination delivery lag for /lagz. Computed per
        request on a fresh connection so a wedged poller or bounced DB shows
        up as 503 rather than a stale-but-200 report. Loads the ruleset per
        call for the same reason a tick does: alert config is policy."""
        import psycopg

        ruleset = load_ruleset(args.rules)
        destinations = [n.destination for n in dbrunner.notifiers_from_ruleset(ruleset)]
        with psycopg.connect(dsn) as conn:
            return dbrunner.delivery_lag(conn, destinations)

    health.start_health_server(health.port_from_env(), health_state, lag_provider)

    # Translate SIGTERM (docker stop / compose down) into a clean loop exit so
    # the container shuts down without a traceback.
    def _handle_term(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _handle_term)
    try:
        poller.poll_forever(dsn, args.rules, interval, batch_size=args.batch_size,
                            health_state=health_state)
    except KeyboardInterrupt:
        print(json.dumps({"event": "guardrail.poll.stop"}), file=sys.stderr)
    return 0


def cmd_llm_judge(args: argparse.Namespace) -> int:
    """run the LLM judge over snippets — the guardrail service's
    instrumented LLM call site (dogfood pilot for the OTLP receiver).

    Telemetry is configured from OTEL_EXPORTER_OTLP_* env (unset = spans are
    computed but not exported). Provider errors are counted, recorded as error
    spans, and do not abort the run — a judge outage must not stop evaluation.
    """
    telemetry.configure()
    judge = LlmJudge.from_env()
    snippets = args.snippets or LLM_JUDGE_DEMO_SNIPPETS

    judged = errors = 0
    for i in range(args.count):
        snippet = snippets[i % len(snippets)]
        try:
            result = judge.judge(snippet)
            judged += 1
            print(json.dumps({"snippet": snippet[:60], **result}))
        except LlmJudgeError as exc:
            errors += 1
            print(json.dumps({"snippet": snippet[:60], "error": str(exc)}), file=sys.stderr)
    try:
        exported = telemetry.flush()
    except Exception as exc:  # noqa: BLE001 — telemetry loss must not fail the run
        exported = 0
        print(json.dumps({"event": "guardrail.telemetry.export_error", "error": str(exc)}), file=sys.stderr)
    print(json.dumps({
        "judged": judged,
        "provider_errors": errors,
        "telemetry_enabled": telemetry.enabled(),
        "spans_exported": exported,
    }), file=sys.stderr)
    return 0


def cmd_validate_rules(args: argparse.Namespace) -> int:
    ruleset = load_ruleset(args.rules)
    print(json.dumps({
        "ok": True,
        "rules": [r["id"] for r in ruleset.rules],
        "version": ruleset.version,
        "policy_hash": ruleset.content_hash,
        "sources": ruleset.sources,
    }))
    return 0


def cmd_repo_ref(args: argparse.Namespace) -> int:
    """print the repo_ref pseudonym a collector would emit for a repo
    path — for verifying restricted_repos entries and crafting seed events."""
    salt = os.environ.get(REPO_REF_SALT_ENV)
    if not salt:
        raise ValueError(f"{REPO_REF_SALT_ENV} is required (the same salt the collectors use)")
    print(repo_ref_for(args.repo, salt))
    return 0


def cmd_notify_test(args: argparse.Namespace) -> int:
    """Prove alert delivery with a synthetic test message.

    Builds notifiers from env (and optional policy alerts.yaml when --rules is
    set) and delivers one test payload to the selected destination. Secrets
    stay env-managed; this is the operator path for "delivery proven with
    test message" / "test page fires" without waiting for a real finding.
    """
    from . import notify
    from .rules import load_ruleset

    env = dict(os.environ)
    notifiers = []
    if args.rules:
        ruleset = load_ruleset(args.rules)
        alerts = (ruleset.settings or {}).get("alerts") or {}
        notifiers = notify.notifiers_from_config(alerts, env)
    else:
        notifiers = notify.notifiers_from_env(env)

    dest = args.destination
    chosen = [n for n in notifiers if getattr(n, "destination", None) == dest]
    if not chosen:
        # Allow an explicit one-shot from CLI flags/env even if policy has not
        # enabled the destination yet (delivery proof path).
        if dest == "email":
            to = args.to or env.get("ALERT_EMAIL_TO") or ""
            smtp = notify._email_smtp_from_env(env)
            n = notify.EmailNotifier(
                **smtp,
                to_addrs=to,
                min_severity=env.get("ALERT_EMAIL_MIN_SEVERITY") or "high",
            )
            chosen = [n]
        elif dest == "pagerduty":
            # routing key is env-only; policy enable is not required
            # for the operator test page (SOC-gated live wiring still is).
            routing_key = env.get("ALERT_PAGERDUTY_ROUTING_KEY") or ""
            if not routing_key:
                print(
                    "error: ALERT_PAGERDUTY_ROUTING_KEY is required for --pagerduty",
                    file=sys.stderr,
                )
                return 2
            n = notify.PagerDutyNotifier(
                routing_key,
                min_severity=env.get("ALERT_PAGERDUTY_MIN_SEVERITY") or "critical",
                triage_base_url=env.get("AIM_BASE_URL") or "",
                source=env.get("ALERT_PAGERDUTY_SOURCE") or "ai-monitoring",
            )
            chosen = [n]
        else:
            print(f"error: no '{dest}' notifier configured", file=sys.stderr)
            return 2

    for n in chosen:
        if hasattr(n, "deliver_test"):
            result = n.deliver_test()
        else:
            # Generic path: deliver a single synthetic finding through deliver().
            finding = notify.build_test_email_finding()
            result = n.deliver([finding])
        print(json.dumps({
            "destination": n.destination,
            "finding_ids": result.finding_ids,
            "http_status": result.http_status,
            "attempts": result.attempts,
        }))
    return 0



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardrail", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_eval = sub.add_parser("evaluate", help="evaluate an NDJSON event stream")
    p_eval.add_argument("--rules", required=True, help="ruleset directory or YAML file")
    p_eval.add_argument("--events", default="-", help="NDJSON events file, or '-' for stdin")
    p_eval.add_argument("--findings", default="-", help="findings NDJSON output, or '-' for stdout")
    p_eval.add_argument("--audit", default=None, help="audit NDJSON output (append-only); omitted = no audit file")
    p_eval.set_defaults(func=cmd_evaluate)

    p_val = sub.add_parser("validate-rules", help="validate a ruleset (CI gate for policy PRs)")
    p_val.add_argument("--rules", required=True)
    p_val.set_defaults(func=cmd_validate_rules)

    p_db = sub.add_parser("evaluate-db", help="evaluate unevaluated Postgres events into the findings table")
    p_db.add_argument("--rules", required=True, help="ruleset directory or YAML file")
    p_db.add_argument("--dsn", default=None, help="Postgres DSN (default: DATABASE_URL env)")
    p_db.add_argument("--batch-size", type=int, default=dbrunner.DEFAULT_BATCH_SIZE)
    p_db.set_defaults(func=cmd_evaluate_db)

    p_poll = sub.add_parser("poll", help="run evaluate-db unattended on an interval (compose service)")
    p_poll.add_argument("--rules", required=True, help="ruleset directory or YAML file")
    p_poll.add_argument("--dsn", default=None, help="Postgres DSN (default: DATABASE_URL env)")
    p_poll.add_argument("--interval", type=float, default=None,
                        help="seconds between polls (default: GUARDRAIL_POLL_INTERVAL env, else 15)")
    p_poll.add_argument("--batch-size", type=int, default=dbrunner.DEFAULT_BATCH_SIZE)
    p_poll.set_defaults(func=cmd_poll)

    p_ref = sub.add_parser("repo-ref", help="print the HMAC repo_ref a collector would emit for a repo path")
    p_ref.add_argument("repo", help="repo working-directory path as the collector sees it")
    p_ref.set_defaults(func=cmd_repo_ref)

    p_judge = sub.add_parser("llm-judge", help="run the instrumented LLM-judge call site (pilot)")
    p_judge.add_argument("snippets", nargs="*", help="snippets to judge (default: built-in demo set)")
    p_judge.add_argument("--count", type=int, default=5, help="total judge calls, cycling the snippet set")
    p_judge.set_defaults(func=cmd_llm_judge)


    p_ntest = sub.add_parser(
        "notify-test",
        help="send a synthetic test alert to a destination",
    )
    p_ntest.add_argument("--email", dest="destination", action="store_const", const="email",
                         help="send a test email via SMTP (ALERT_EMAIL_* env)")
    p_ntest.add_argument("--pagerduty", dest="destination", action="store_const", const="pagerduty",
                         help="fire a PagerDuty Events API v2 test page (ALERT_PAGERDUTY_ROUTING_KEY)")
    p_ntest.add_argument(
        "--destination",
        choices=["email", "webhook", "google_chat", "sentinel", "pagerduty", "slack"],
        help="destination to test (default: --email)",
    )
    p_ntest.add_argument("--to", default=None, help="override recipients for email test")
    p_ntest.add_argument("--rules", default=None, help="optional ruleset dir to load settings.alerts")
    p_ntest.set_defaults(func=cmd_notify_test, destination="email")
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (RulesetError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
