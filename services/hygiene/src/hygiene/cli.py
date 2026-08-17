"""`hygiene` — on-demand and scheduled entry point.

    hygiene scan ./repo                      # one checkout, report to stdout
    hygiene scan ./repo --publish            # …and onto the alert bus
    hygiene scan --all --publish             # every repo in the config file
    hygiene audit-token                      # check 3 on its own

Exit codes are the contract with cron and with CI:

    0  ran clean
    1  ran, and found something at or above --fail-on (default: never)
    2  DID NOT RUN CORRECTLY — a check errored, or an alert was rejected

2 is separate from 1 on purpose. A scheduler that treats "found secrets" and
"the scanner is broken" as the same signal will eventually page on the wrong
one, and the broken scanner is the more urgent of the two.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import bus, config as config_mod, orchestrator, report as report_mod
from .checks import liveness, tokens
from .models import SEVERITY_ORDER, load_or_create_key


def _log(payload: dict) -> None:
    print(json.dumps(payload), file=sys.stderr, flush=True)


def _verifier(enabled: bool):
    """The liveness callable handed to the history check.

    Disabled means "do not probe", expressed as a function that says so rather
    than as `None`, so the finding records *why* it is unverified instead of
    silently coming back `not_checked`.
    """
    if enabled:
        return liveness.verify
    return lambda issuer, **kw: liveness.Result(
        "unknown", reason="liveness verification disabled by configuration")


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = config_mod.load(args.config)
    if args.no_liveness:
        cfg.liveness_enabled = False
    if args.state_dir:
        cfg.state_dir = args.state_dir

    targets = [args.repo] if args.repo else list(cfg.repos)
    if not targets:
        print("no repositories to scan: pass a path or set scan.repos in the config",
              file=sys.stderr)
        return 2

    key = load_or_create_key(cfg.key_path)
    store = None
    if not args.no_store:
        from .store import Store
        store = Store(cfg.db_path, retention_days=cfg.retention_days)
        # Retention runs before the scan, every run. See store.purge.
        purged = store.purge()
        _log({"event": "hygiene.retention.purge", "rows": purged,
              "retention_days": cfg.retention_days})

    publisher = None
    if args.publish:
        publisher = bus.Publisher(stream_key=cfg.stream_key or bus.STREAM_KEY)

    worst_seen = ""
    broken = False
    for target in targets:
        repo_dir = os.path.abspath(target)
        label = args.repo_name or orchestrator.repo_label(repo_dir)
        run = orchestrator.scan_repo(
            repo_dir, repo=label, key=key,
            verify=_verifier(cfg.liveness_enabled),
            github_token=cfg.github_token if not args.no_token_audit else "",
            minimum_scopes=cfg.minimum_scopes,
            ciem_base=cfg.ciem_base_url,
            gitleaks_config=cfg.gitleaks_config)

        text = report_mod.render(run, retention_days=cfg.retention_days)
        if args.json:
            print(json.dumps({
                "repo": label, "ok": run.ok, "ran": run.ran, "errors": run.errors,
                "counts": run.counts(),
                "findings": [{
                    "check": f.check, "rule_id": f.rule_id, "finding_type": f.finding_type,
                    "severity": bus.severity_for(f), "repo": f.repo, "path": f.path,
                    "line": f.line, "commit": f.commit, "masked": f.masked,
                    "fingerprint": f.fingerprint, "liveness": f.liveness,
                    "liveness_detail": f.liveness_detail, "title": f.title,
                    "remediation": f.remediation,
                } for f in run.by_severity()],
            }, indent=2))
        else:
            print(text)

        if args.report_dir or cfg.report_dir:
            directory = args.report_dir or cfg.report_dir
            os.makedirs(directory, exist_ok=True)
            path = os.path.join(directory, f"{label.replace('/', '_')}.md")
            with open(path, "w") as fh:
                fh.write(text)
            _log({"event": "hygiene.report.written", "path": path})

        if publisher is not None:
            delivered = orchestrator.publish(run, publisher, store)
            _log({"event": "hygiene.published", "repo": label, "alerts": len(delivered),
                  "rejected": publisher.rejected})
        elif store is not None:
            for finding in run.findings:
                store.record(finding)

        for finding in run.findings:
            severity = bus.severity_for(finding)
            if not worst_seen or SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(worst_seen):
                worst_seen = severity
        if not run.ok:
            broken = True
            _log({"event": "hygiene.check.failed", "repo": label, "errors": run.errors})

    if store is not None:
        store.close()
    if broken or (publisher is not None and publisher.rejected):
        return 2
    if args.fail_on and worst_seen and \
            SEVERITY_ORDER.index(worst_seen) <= SEVERITY_ORDER.index(args.fail_on):
        return 1
    return 0


def cmd_audit_token(args: argparse.Namespace) -> int:
    """Check 3 alone — the fastest way to answer "what can this token do?"."""
    cfg = config_mod.load(args.config)
    token = cfg.github_token
    if not token:
        print("no token: set HYGIENE_GITHUB_TOKEN or GITHUB_TOKEN", file=sys.stderr)
        return 2
    audit = tokens.audit_github(token)
    findings = tokens.findings_for_token(audit, repo=args.repo_name or "(token)",
                                         minimum=cfg.minimum_scopes)
    print(json.dumps({
        "identity": audit.identity, "token_kind": audit.token_kind,
        "scopes_enumerable": audit.enumerable, "granted": list(audit.granted),
        "minimum": cfg.minimum_scopes, "reason": audit.reason,
        "findings": [{"severity": f.severity, "title": f.title,
                      "remediation": f.remediation} for f in findings],
    }, indent=2))
    return 1 if findings and args.fail_on else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hygiene", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=os.environ.get("HYGIENE_CONFIG", ""),
                        help="path to hygiene.yml")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run all three checks over a repository")
    scan.add_argument("repo", nargs="?", help="path to a git checkout")
    scan.add_argument("--all", action="store_true", help="scan every repo in the config")
    scan.add_argument("--repo-name", default="", help="override the owner/name label")
    scan.add_argument("--publish", action="store_true", help="publish findings to the alert bus")
    scan.add_argument("--json", action="store_true", help="machine-readable output")
    scan.add_argument("--report-dir", default="", help="also write the markdown report here")
    scan.add_argument("--state-dir", default="", help="override the state directory")
    scan.add_argument("--no-store", action="store_true", help="do not persist findings state")
    scan.add_argument("--no-liveness", action="store_true",
                      help="never send a credential to its issuer")
    scan.add_argument("--no-token-audit", action="store_true", help="skip check 3")
    scan.add_argument("--fail-on", choices=SEVERITY_ORDER, default="",
                      help="exit 1 when a finding at or above this severity is present")
    scan.set_defaults(func=cmd_scan)

    audit = sub.add_parser("audit-token", help="check 3 on its own")
    audit.add_argument("--repo-name", default="")
    audit.add_argument("--fail-on", action="store_true",
                       help="exit 1 when the token is over-scoped")
    audit.set_defaults(func=cmd_audit_token)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
