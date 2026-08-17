"""`gatehouse` CLI — the same pipeline the webhook runs, without GitHub.

This is not a convenience wrapper. It is how the scan half of the service is
tested, demoed and debugged: `gatehouse scan` on a local checkout exercises
diff scoping, all four scanners, dedupe, suppression and the alert mapping with
no App credentials, no webhook and no network. Anything that only works behind
a GitHub App is a thing nobody can reproduce when it misbehaves at 2am.

It also makes gatehouse usable as a plain CI step for repos that are not on
GitHub — exit code 1 when something blocks.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from . import bus, checkrun, orchestrator, suppress, telemetry
from .cache import Store
from .models import ScanTarget


def _flush_telemetry() -> None:
    """Best-effort OTLP flush — telemetry loss must never fail a gate."""
    try:
        telemetry.flush()
    except Exception:  # noqa: BLE001
        pass


def _scan(args: argparse.Namespace) -> int:
    telemetry.configure()
    repo_dir = os.path.abspath(args.repo_dir)
    target = ScanTarget(
        repo_full_name=args.repo_name, pr_number=args.pr,
        base_sha=args.base or "", head_sha=args.head or "")
    store = None if args.no_cache else Store(args.state_db)
    config_text = ""
    if args.config and os.path.exists(args.config):
        with open(args.config) as fh:
            config_text = fh.read()
    elif not args.config:
        default = os.path.join(repo_dir, suppress.CONFIG_NAME)
        if os.path.exists(default):
            # Local runs read the file from the working tree. The webhook path
            # deliberately does not (see suppress.py) — there is no base branch
            # to read from here, and the operator is the repo owner anyway.
            with open(default) as fh:
                config_text = fh.read()

    publisher = bus.Publisher() if args.publish else None
    result = orchestrator.scan(
        repo_dir, target, store=store, config_text=config_text,
        base_ref=args.base or "", enabled=args.scanner or None,
        publisher=publisher, all_files=args.all, ai=args.ai)

    if args.json:
        print(json.dumps({
            "conclusion": result.conclusion,
            "findings": [asdict(f) for f in result.findings],
            "suppressed": [{"finding": asdict(f), "reason": r} for f, r in result.suppressed],
            "resolved": result.resolved,
            "errors": result.errors,
            "config_problems": result.config_problems,
            "alerts": result.alerts,
            "scanned_files": result.scanned_files,
            "cached_files": result.cached_files,
            "duration_ms": result.duration_ms,
            "ai_stats": result.ai_stats,
        }, indent=2))
    else:
        print(checkrun.title(result.findings, result.errors))
        print(checkrun.summary(
            result.findings, suppressed=result.suppressed, errors=result.errors,
            config_problems=result.config_problems, scanned_files=result.scanned_files,
            cached_files=result.cached_files, duration_ms=result.duration_ms,
            ai_stats=result.ai_stats, ai_blocking=result.ai_blocking))

    if store:
        store.close()
    _flush_telemetry()
    # `neutral` is exit 0: it means "look at this", not "stop". Only a real
    # blocking finding fails the command.
    return 1 if result.conclusion == "failure" else 0


def _serve(args: argparse.Namespace) -> int:
    telemetry.configure()
    from .server import serve

    serve(port=args.port)
    return 0


def _prune(args: argparse.Namespace) -> int:
    store = Store(args.state_db)
    removed = store.prune(days=args.days)
    print(json.dumps({"removed_rows": removed, "retention_days": args.days}))
    store.close()
    return 0


def _evidence(args: argparse.Namespace) -> int:
    """Retrieve / prune durable gate verdicts (≥90 day retention)."""
    from . import evidence as evidence_mod

    store = evidence_mod.EvidenceStore(args.db)
    try:
        if args.evidence_command == "get":
            rows = store.get(
                repo=args.repo or None,
                head_sha=args.sha or None,
                merge_sha=args.merge_sha or None,
                pr_number=args.pr if args.pr is not None else None,
            )
            payload = [r.to_dict() for r in rows]
            print(json.dumps(payload if args.all else (payload[:1] if payload else []), indent=2))
            return 0 if payload else 1
        if args.evidence_command == "list":
            rows = store.list_recent(limit=args.limit, repo=args.repo or None)
            print(json.dumps([r.to_dict() for r in rows], indent=2))
            return 0
        if args.evidence_command == "prune":
            removed = store.prune(days=args.days)
            print(json.dumps({
                "removed_rows": removed,
                "retention_days": args.days if args.days is not None else evidence_mod.retention_days(),
                "db": store.path,
            }))
            return 0
        print(f"unknown evidence subcommand: {args.evidence_command}", file=sys.stderr)
        return 2
    finally:
        store.close()


def _check_tokens(args: argparse.Namespace) -> int:
    """Non-secret PAT readiness / fail-closed scope self-check."""
    from . import token_check

    repos = list(args.repo or []) or None
    report = token_check.check_tokens(
        read_token=args.token or None,
        write_token=args.revert_token if args.revert_token else None,
        repos=repos,
        require_fine_grained=args.require_fine_grained,
        require_write=not args.no_require_write,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(token_check.format_human(report))
    if not report.ok:
        return 1
    return 0


def _merge_audit(args: argparse.Namespace) -> int:
    """Out-of-band merge auditor. Does not share a GH Actions failure domain."""
    from . import merge_audit

    token = args.token or os.environ.get("GATEHOUSE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if not token:
        print("GATEHOUSE_GITHUB_TOKEN (or --token) is required", file=sys.stderr)
        return 2

    publisher = bus.Publisher() if args.publish else None
    gate_cfg = None
    if args.gate:
        with open(args.gate) as fh:
            gate_cfg = merge_audit.load_gate_config(fh.read())

    repos, base_refs = merge_audit.parse_repo_specs(args.repo, args.base_ref)

    if args.loop:
        merge_audit.poll_forever(
            repos, token, interval_s=args.interval, publisher=publisher,
            gate_cfg=gate_cfg, limit=args.limit, since_iso=args.since or "",
            revert_token=args.revert_token or os.environ.get("GATEHOUSE_REVERT_TOKEN", ""),
            base_refs=base_refs,
        )
        return 0

    results = []
    for repo in repos:
        results.extend(merge_audit.run_audit_once(
            repo, token, publisher=publisher, gate_cfg=gate_cfg,
            limit=args.limit, since_iso=args.since or "",
            revert_token=args.revert_token or os.environ.get("GATEHOUSE_REVERT_TOKEN", ""),
            base_ref=base_refs[repo],
        ))

    payload = []
    exit_code = 0
    for r in results:
        if r.bypasses or r.unverified:
            exit_code = 1
        payload.append({
            "pr": r.pr_number,
            "head_sha": r.head_sha,
            "clean": r.clean,
            "unverified": r.unverified,
            "bypasses": [b.to_dict() for b in r.bypasses],
            "alerts": len(r.alerts),
            "revert_pr": r.revert_pr,
            "notes": r.notes,
        })
    print(json.dumps({"repo": args.repo, "results": payload}, indent=2))
    return exit_code


def _iac_parity(args: argparse.Namespace) -> int:
    """Report / fail on IaC↔CNAPP rule parity drift."""
    from . import cnapp_parity

    report = cnapp_parity.check_drift(
        mapping_path=args.mapping or None,
        catalog_path=args.catalog or None,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary_md())
        if not report.ok:
            detail = report.to_dict()
            for key in (
                "unknown_cnapp_targets",
                "unmapped_required_cnapp",
                "unmapped_watchlist",
                "duplicate_mappings",
            ):
                if detail[key]:
                    print(f"{key}:", ", ".join(detail[key]), file=sys.stderr)
    return 0 if report.ok else 1


def _iac_scan(args: argparse.Namespace) -> int:
    """Full-tree Terraform + K8s Checkov scan with CNAPP parity labels.

    Diff-scoped PR path stays on `gatehouse scan` (GitHub App). This command is
    the CI job on the self-hosted runner: scan known IaC roots, attach would-be
    cloud findings, exit 1 when findings meet the fail-on threshold.
    """
    from dataclasses import asdict

    from . import checkrun, cnapp_parity
    from .scanners import checkov as checkov_scanner

    repo_dir = os.path.abspath(args.repo_dir)
    paths = list(args.path) if args.path else cnapp_parity.discover_iac_paths(repo_dir)
    if args.changed_only and args.base:
        # Optional PR-scoped mode for CI when only IaC files changed.
        from . import diffscope
        scope = diffscope.compute(repo_dir, base=args.base)
        paths = [p for p in paths if p in set(scope.paths)]

    if not paths:
        msg = "No Terraform/K8s IaC paths to scan."
        if args.json:
            print(json.dumps({"conclusion": "success", "findings": [], "note": msg}))
        else:
            print(msg)
        # Still enforce parity map integrity even when the tree has no IaC.
        if args.parity_check:
            return _iac_parity(args)
        return 0

    if args.parity_check:
        parity_rc = _iac_parity(argparse.Namespace(
            mapping=args.mapping, catalog=args.catalog, json=False))
        if parity_rc != 0:
            return parity_rc

    outcome = checkov_scanner.scan(repo_dir, paths)
    if outcome.error:
        print(f"checkov error: {outcome.error}", file=sys.stderr)
        return 2

    findings = cnapp_parity.enrich_findings(
        outcome.findings, align_severity=cnapp_parity.env_align_severity())
    fail_on = args.fail_on or checkrun.FAIL_ON
    conclusion = checkrun.conclusion(findings, errors=[], fail_on=fail_on)
    would_be = cnapp_parity.would_be_cloud_findings(findings)
    section = cnapp_parity.render_would_be_section(findings)

    if args.json:
        print(json.dumps({
            "conclusion": conclusion,
            "fail_on": fail_on,
            "scanned_paths": paths,
            "findings": [asdict(f) for f in findings],
            "would_be_cloud": [asdict(w) for w in would_be],
            "summary_md": section,
        }, indent=2))
    else:
        print(checkrun.title(findings, []))
        print(section or "No CNAPP-mapped IaC findings.")
        if args.github_step_summary:
            with open(args.github_step_summary, "a", encoding="utf-8") as fh:
                fh.write("### IaC scan (CNAPP parity)\n\n")
                fh.write(checkrun.title(findings, []) + "\n\n")
                fh.write((section or "No CNAPP-mapped IaC findings.") + "\n")
        if args.comment_out:
            body = checkrun.comment_body(
                (section or "No CNAPP-mapped IaC findings.")
                + f"\n\n<sub>CI IaC scan — {len(paths)} path(s), "
                f"threshold `{fail_on}`.</sub>"
            )
            with open(args.comment_out, "w", encoding="utf-8") as fh:
                fh.write(body)

    return 1 if conclusion == "failure" else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gatehouse", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a checkout the way the PR gate would")
    scan.add_argument("--repo-dir", default=".")
    scan.add_argument("--repo-name", default="local/repo",
                      help="owner/name — becomes the alert's resource.ref")
    scan.add_argument("--pr", type=int, default=0)
    scan.add_argument("--base", default="",
                      help="base ref for the diff (default: merge-base with refs/gatehouse/base)")
    scan.add_argument("--head", default="")
    scan.add_argument("--all", action="store_true",
                      help="ignore the diff and scan every tracked file (baseline mode)")
    scan.add_argument("--scanner", action="append",
                      help="limit to one scanner; repeatable")
    scan.add_argument("--config", default="", help=f"path to {suppress.CONFIG_NAME}")
    scan.add_argument("--state-db", default=os.environ.get("GATEHOUSE_STATE_DB", ":memory:"))
    scan.add_argument("--no-cache", action="store_true")
    scan.add_argument("--ai", dest="ai", action="store_true", default=True,
                      help="run the AI security reviewer when GATEHOUSE_AI_PROVIDER "
                           "is configured (default)")
    scan.add_argument("--no-ai", dest="ai", action="store_false",
                      help="skip the AI reviewer even when configured")
    scan.add_argument("--publish", action="store_true", help="publish alerts to the bus")
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=_scan)

    serve = sub.add_parser("serve", help="run the GitHub App webhook receiver")
    serve.add_argument("--port", type=int, default=int(os.environ.get("GATEHOUSE_PORT", "8090")))
    serve.set_defaults(func=_serve)

    prune = sub.add_parser("prune", help="enforce the finding-cache retention limit")
    prune.add_argument("--state-db", default=os.environ.get("GATEHOUSE_STATE_DB",
                                                            "/var/lib/gatehouse/state.db"))
    prune.add_argument("--days", type=int, default=30)
    prune.set_defaults(func=_prune)

    audit = sub.add_parser(
        "merge-audit",
        help="out-of-band merge auditor — detect/attribute/revert bypasses",
    )
    audit.add_argument("--repo", action="append", required=True,
                       help="owner/name[:base-ref]; repeatable — the ref suffix "
                            "overrides --base-ref for that repo only")
    audit.add_argument("--token", default="",
                       help="GitHub token (default: GATEHOUSE_GITHUB_TOKEN / GITHUB_TOKEN)")
    audit.add_argument("--revert-token", default="",
                       help="token with contents:write for auto-revert (GATEHOUSE_REVERT_TOKEN)")
    audit.add_argument("--gate", default="",
                       help="path to required-checks.json (else fetch from repo default branch)")
    audit.add_argument("--base-ref", default="main")
    audit.add_argument("--since", default="",
                       help="only audit merges with merged_at >= this ISO timestamp")
    audit.add_argument("--limit", type=int, default=20)
    audit.add_argument("--publish", action="store_true",
                       help="publish bypass alerts to the security.alert bus")
    audit.add_argument("--loop", action="store_true",
                       help="poll forever (failure domain = this process, not Actions)")
    audit.add_argument("--interval", type=int, default=120,
                       help="poll interval seconds when --loop (default 120)")
    audit.set_defaults(func=_merge_audit)

    tok = sub.add_parser(
        "check-tokens",
        help="Fail-closed PAT readiness check (shape + non-mutating "
             "capability probes; never prints secret values)",
    )
    tok.add_argument("--repo", action="append", default=[],
                     help="owner/name to probe; repeatable "
                          "(default: GATEHOUSE_AUDIT_REPO / twin)")
    tok.add_argument("--token", default="",
                     help="override read token (default: GATEHOUSE_GITHUB_TOKEN / GITHUB_TOKEN)")
    tok.add_argument("--revert-token", default="",
                     help="override write token (default: GATEHOUSE_REVERT_TOKEN)")
    tok.add_argument("--require-fine-grained", action="store_true",
                     help="fail unless both tokens are github_pat_* (post-cutover gate)")
    tok.add_argument("--no-require-write", action="store_true",
                     help="detect-only mode: missing/weak REVERT token is a warning")
    tok.add_argument("--json", action="store_true",
                     help="machine-readable report (no secret values)")
    tok.set_defaults(func=_check_tokens)

    evidence = sub.add_parser(
        "evidence",
        help="Retrieve / prune durable gate verdicts (≥90 days)",
    )
    evidence.add_argument(
        "--db",
        default=os.environ.get("GATEHOUSE_EVIDENCE_DB", ""),
        help="path to gate-evidence.db (default: GATEHOUSE_EVIDENCE_DB or sibling of state.db)",
    )
    e_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    e_get = e_sub.add_parser("get", help="look up verdicts by SHA / PR / merge commit")
    e_get.add_argument("--repo", default="")
    e_get.add_argument("--sha", default="", help="PR head SHA")
    e_get.add_argument("--merge-sha", default="", help="merge commit SHA on the base branch")
    e_get.add_argument("--pr", type=int, default=None)
    e_get.add_argument("--all", action="store_true",
                       help="return every matching row (default: newest only)")
    e_get.set_defaults(func=_evidence)
    e_list = e_sub.add_parser("list", help="list recent evidence rows")
    e_list.add_argument("--repo", default="")
    e_list.add_argument("--limit", type=int, default=50)
    e_list.set_defaults(func=_evidence)
    e_prune = e_sub.add_parser("prune", help="delete rows older than retention")
    e_prune.add_argument("--days", type=int, default=None,
                         help="override GATEHOUSE_EVIDENCE_RETENTION_DAYS (default 90)")
    e_prune.set_defaults(func=_evidence)

    parity = sub.add_parser(
        "iac-parity",
        help="check IaC rule ↔ CNAPP posture rule mapping for drift",
    )
    parity.add_argument("--mapping", default="", help="override mapping.yml path")
    parity.add_argument("--catalog", default="", help="override posture_catalog.yml path")
    parity.add_argument("--json", action="store_true")
    parity.set_defaults(func=_iac_parity)

    iac = sub.add_parser(
        "iac-scan",
        help="scan Terraform + K8s with Checkov and CNAPP parity labels",
    )
    iac.add_argument("--repo-dir", default=".")
    iac.add_argument("--path", action="append",
                     help="repo-relative path to scan; repeatable (default: discover)")
    iac.add_argument("--base", default="",
                     help="with --changed-only, only scan files changed vs this ref")
    iac.add_argument("--changed-only", action="store_true",
                     help="intersect discovered paths with the git diff vs --base")
    iac.add_argument("--fail-on", default=os.environ.get("GATEHOUSE_FAIL_ON", "high"),
                     help="severity threshold that fails the check (block_on)")
    iac.add_argument("--parity-check", action="store_true", default=True,
                     help="fail if the IaC↔CNAPP map drifts (default on)")
    iac.add_argument("--no-parity-check", dest="parity_check", action="store_false")
    iac.add_argument("--mapping", default="")
    iac.add_argument("--catalog", default="")
    iac.add_argument("--json", action="store_true")
    iac.add_argument("--comment-out", default="",
                     help="write a gatehouse PR comment body (would-be cloud findings)")
    iac.add_argument("--github-step-summary", default=os.environ.get("GITHUB_STEP_SUMMARY", ""),
                     help="append markdown to this file (CI step summary)")
    iac.set_defaults(func=_iac_scan)

    version = sub.add_parser("version")
    version.set_defaults(func=lambda _: (print(orchestrator.VERSION), 0)[1])

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
