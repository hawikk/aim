#!/usr/bin/env python3
"""Apply or verify declarative branch protection (AIM-298).

`.github/branch-protection.json` is the desired state. This script is the only
supported way to push it to GitHub, so the 403-configured-by-hand situation
cannot recur as silent drift: either the file matches live state, or the script
prints the exact missing permission / plan-tier message.

Usage:
  python3 scripts/apply_branch_protection.py --check
  python3 scripts/apply_branch_protection.py --apply
  python3 scripts/apply_branch_protection.py --self-test

Exit codes:
  0  protection matches (or apply succeeded)
  1  drift / apply failed for a retriable reason
  2  plan-tier or permission gap (not fixable by re-running without a plan change)
  3  usage / local config error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = REPO_ROOT / ".github" / "branch-protection.json"
API = os.environ.get("GITHUB_API", "https://api.github.com")


def _load(path: Path) -> dict:
    with path.open() as fh:
        return json.load(fh)


def _token() -> str:
    return (
        os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
        or os.environ.get("GATEHOUSE_GITHUB_TOKEN")
        or ""
    )


def _request(method: str, url: str, token: str, body: dict | None = None) -> tuple[int, dict | list | str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "aim-apply-branch-protection/0.1")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
        try:
            payload = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            payload = {"message": raw.decode("utf-8", "replace")[:500]}
        return status, payload
    if not raw:
        return status, {}
    try:
        return status, json.loads(raw.decode())
    except json.JSONDecodeError:
        return status, raw.decode("utf-8", "replace")


def _protection_url(cfg: dict) -> str:
    owner = cfg["owner"]
    repo = cfg["repo"]
    branch = cfg["branch"]
    return f"{API}/repos/{owner}/{repo}/branches/{branch}/protection"


def _classify_failure(status: int, payload: dict | list | str, cfg: dict) -> tuple[int, str]:
    """Return (exit_code, human message). 2 = plan/permission gap."""
    msg = ""
    if isinstance(payload, dict):
        msg = str(payload.get("message") or payload)
    else:
        msg = str(payload)

    gap = cfg.get("missing_capability") or {}
    plan_needle = gap.get("plan_message_contains") or "Upgrade to GitHub Pro"
    if status == 403 and plan_needle.lower() in msg.lower():
        return 2, (
            f"branch protection unavailable on this plan (HTTP 403).\n"
            f"  GitHub said: {msg}\n"
            f"  Required plan: {gap.get('required_plan', 'GitHub Pro')}\n"
            f"  This is NOT a missing token scope — upgrading the plan (or making\n"
            f"  the repo public / moving to an org with branch protection) is the fix.\n"
            f"  If the plan were available, token would still need: "
            f"{gap.get('required_permission_if_plan_ok', 'repo admin')}\n"
            f"  scopes: {gap.get('required_token_scopes_if_plan_ok')}\n"
            f"  Tier-1 fallback (enforcing without native protection): "
            f"{gap.get('tier1_fallback', 'docs/security/enforcing-ci-gates.md')}"
        )

    if status == 403:
        return 2, (
            f"HTTP 403 applying branch protection.\n"
            f"  GitHub said: {msg}\n"
            f"  Missing permission (most likely): "
            f"{gap.get('required_permission_if_plan_ok', 'Administration: Read and write')}\n"
            f"  Token scopes required: {gap.get('required_token_scopes_if_plan_ok', ['repo'])}\n"
            f"  Re-run with a token that has repo admin, or ask an org owner to grant it."
        )

    if status == 404:
        return 1, f"branch or repo not found (HTTP 404): {msg}"

    return 1, f"HTTP {status}: {msg}"


def _desired_body(cfg: dict) -> dict:
    """Shape the PUT body GitHub's branch protection API expects."""
    p = dict(cfg["protection"])
    # GitHub wants nested objects with specific keys; pass through as declared.
    body = {
        "required_status_checks": p.get("required_status_checks"),
        "enforce_admins": p.get("enforce_admins", True),
        "required_pull_request_reviews": p.get("required_pull_request_reviews"),
        "restrictions": p.get("restrictions"),
        "required_linear_history": p.get("required_linear_history", True),
        "allow_force_pushes": p.get("allow_force_pushes", False),
        "allow_deletions": p.get("allow_deletions", False),
        "block_creations": p.get("block_creations", False),
        "required_conversation_resolution": p.get("required_conversation_resolution", True),
    }
    return body


def _repo_url(cfg: dict) -> str:
    return f"{API}/repos/{cfg['owner']}/{cfg['repo']}"


def check_repo_settings(cfg: dict, token: str) -> tuple[int, dict]:
    """Verify repo-level settings that remain enforceable without branch protection.

    AIM-404: native ``allow_auto_merge`` must stay false on free private repos —
    without required status checks, GitHub auto-merge lands the moment the PR
    is conflict-free (PR #96). The labeled ``auto-merge.yml`` workflow is the
    only approved automated merge path.
    """
    desired = cfg.get("repo_settings") or {}
    # Strip doc-only keys.
    desired = {k: v for k, v in desired.items() if not str(k).startswith("_")}
    if not desired:
        return 0, {"state": "skipped", "reason": "no repo_settings in config"}

    status, payload = _request("GET", _repo_url(cfg), token)
    if status != 200 or not isinstance(payload, dict):
        return 1, {
            "state": "error",
            "http_status": status,
            "message": (
                payload.get("message") if isinstance(payload, dict) else str(payload)
            ),
        }

    mismatches: dict[str, dict] = {}
    observed: dict[str, object] = {}
    for key, want in desired.items():
        got = payload.get(key)
        observed[key] = got
        if got != want:
            mismatches[key] = {"desired": want, "live": got}

    if mismatches:
        return 1, {
            "state": "drift",
            "mismatches": mismatches,
            "observed": observed,
            "remediation": (
                "Set allow_auto_merge=false (Settings → General → Pull Requests, "
                "or PATCH /repos/{owner}/{repo} {\"allow_auto_merge\": false}). "
                "Use the labeled auto-merge.yml workflow or scripts/agent_safe_merge.py."
            ),
        }
    return 0, {"state": "match", "observed": observed}


def check(cfg: dict, token: str) -> int:
    # Always evaluate repo_settings first — these work even when branch
    # protection is a plan-tier 403 (AIM-404 residual control).
    settings_code, settings_report = check_repo_settings(cfg, token)
    if settings_code != 0:
        print(json.dumps({"repo_settings": settings_report}, indent=2), file=sys.stderr)
        if settings_report.get("state") == "drift":
            print(
                "AIM-404 control drift: repo_settings do not match policy "
                f"({settings_report.get('mismatches')}).",
                file=sys.stderr,
            )
        # Continue to also report branch-protection status, but fail closed.

    status, payload = _request("GET", _protection_url(cfg), token)
    if status == 200 and isinstance(payload, dict):
        desired_contexts = set(
            ((cfg.get("protection") or {}).get("required_status_checks") or {}).get("contexts") or []
        )
        live = payload.get("required_status_checks") or {}
        # contexts vs checks depending on API version
        live_contexts = set(live.get("contexts") or [])
        if not live_contexts and live.get("checks"):
            live_contexts = {c.get("context") for c in live["checks"] if c.get("context")}
        missing = sorted(desired_contexts - live_contexts)
        extra = sorted(live_contexts - desired_contexts)
        print(json.dumps({
            "state": "configured",
            "branch": cfg["branch"],
            "live_contexts": sorted(live_contexts),
            "desired_contexts": sorted(desired_contexts),
            "missing_from_live": missing,
            "extra_on_live": extra,
            "match": not missing and not extra,
            "repo_settings": settings_report,
        }, indent=2))
        if settings_code != 0:
            return settings_code
        return 0 if not missing else 1

    code, message = _classify_failure(status, payload, cfg)
    print(message, file=sys.stderr)
    print(json.dumps({
        "state": "unavailable" if code == 2 else "error",
        "http_status": status,
        "tier1_fallback": (cfg.get("missing_capability") or {}).get("tier1_fallback"),
        "repo_settings": settings_report,
    }, indent=2))
    # Protection plan-gap (exit 2) is expected on free private; still fail if
    # repo_settings drifted (exit 1). Prefer the stronger signal for CI.
    if settings_code != 0:
        return settings_code
    return code


def apply(cfg: dict, token: str) -> int:
    if not token:
        print("GITHUB_TOKEN is required for --apply", file=sys.stderr)
        return 3
    status, payload = _request("PUT", _protection_url(cfg), token, _desired_body(cfg))
    if status in (200, 201) and isinstance(payload, dict):
        print(json.dumps({"state": "applied", "branch": cfg["branch"],
                          "url": _protection_url(cfg)}, indent=2))
        return 0
    code, message = _classify_failure(status, payload, cfg)
    print(message, file=sys.stderr)
    print(json.dumps({
        "state": "unavailable" if code == 2 else "error",
        "http_status": status,
        "message": message.split("\n")[0],
        "tier1_fallback": (cfg.get("missing_capability") or {}).get("tier1_fallback"),
    }, indent=2))
    return code


def self_test() -> int:
    """No network: classify known 403 payloads."""
    cfg = {
        "missing_capability": {
            "plan_message_contains": "Upgrade to GitHub Pro",
            "required_plan": "GitHub Pro",
            "required_permission_if_plan_ok": "Administration: Read and write",
            "required_token_scopes_if_plan_ok": ["repo"],
            "tier1_fallback": "docs/security/enforcing-ci-gates.md",
        }
    }
    code, msg = _classify_failure(
        403,
        {"message": "Upgrade to GitHub Pro or make this repository public to enable this feature.",
         "status": "403"},
        cfg,
    )
    assert code == 2, code
    assert "Upgrade to GitHub Pro" in msg
    assert "NOT a missing token scope" in msg

    code2, msg2 = _classify_failure(
        403,
        {"message": "Resource not accessible by integration"},
        cfg,
    )
    assert code2 == 2
    assert "Administration" in msg2 or "permission" in msg2.lower()

    # Desired body shape
    body = _desired_body({
        "protection": {
            "required_status_checks": {"strict": True, "contexts": ["secret scan"]},
            "enforce_admins": True,
            "required_pull_request_reviews": {"required_approving_review_count": 1},
            "restrictions": None,
        }
    })
    assert body["required_status_checks"]["contexts"] == ["secret scan"]

    # AIM-404: shipped config declares allow_auto_merge=false (no network).
    shipped = _load(DEFAULT_CONFIG)
    assert shipped.get("repo_settings", {}).get("allow_auto_merge") is False, (
        "AIM-404: branch-protection.json must pin allow_auto_merge=false"
    )

    print("self-test ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--apply", action="store_true")
    g.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.config.exists():
        print(f"config not found: {args.config}", file=sys.stderr)
        return 3
    cfg = _load(args.config)
    token = _token()
    if args.check:
        return check(cfg, token)
    return apply(cfg, token)


if __name__ == "__main__":
    sys.exit(main())
