"""Repo coverage ledger (AIM-332) — gated vs dark, truthfully.

The Coverage & Trust screen (AIM-278) already answers "what are we NOT
seeing?" for AI tools and cloud accounts. Repos were partial: known from
events that phoned home, covered/dark unknown. This module is the missing
denominator for CI gates:

  known   = every repo the forge (GitHub App installations) reports, plus
            optional org inventory (so selective installs cannot hide
            un-onboarded repos as "not existing"), plus any repo that has
            a gate_run row (so a de-installed repo stays visible as dark).
  covered = onboarded, not policy-excluded, and last gate run within the
            staleness window.
  dark    = known but not covered, with an explicit reason — never implied
            green from silence.

Dark reasons (stable ids the UI can pill on):

  not_onboarded     in org inventory, not on any installation
  policy_excluded   matched an explicit exclusion list (AIM-331 forward)
  never_scanned     installed, no gate_run ever recorded
  runner_offline    installed + has history, but last run older than threshold
  forge_error       forge enumeration failed for this installation (partial)

Honesty rules match AIM-278 / AIM-276: missing forge credentials yield an
explicit `not_wired` shape rather than an empty green ledger.
"""

from __future__ import annotations

import json
import os
import time
from typing import Iterable

from .cache import Store
from .github import Client, GitHubError
from .scanners.base import log

# Default: a gated repo that has not produced a gate run in 7 days is dark.
# Overridable so pilots with quieter merge cadence can loosen without a deploy.
DEFAULT_STALE_SECONDS = int(os.environ.get(
    "GATEHOUSE_COVERAGE_STALE_SECONDS", str(7 * 24 * 3600)))

DARK_NOT_ONBOARDED = "not_onboarded"
DARK_POLICY_EXCLUDED = "policy_excluded"
DARK_NEVER_SCANNED = "never_scanned"
DARK_RUNNER_OFFLINE = "runner_offline"
DARK_FORGE_ERROR = "forge_error"

DEFINITIONS = {
    "repos_known": (
        "Union of forge installation repos, optional org inventory, and any "
        "repo that has ever produced a gate run. Absence is shown, never "
        "implied green."
    ),
    "repos_covered": (
        "Onboarded (on an installation), not policy-excluded, last gate run "
        "within the staleness window."
    ),
    "repos_dark": (
        "Known but not covered. Each entry carries a reason: not_onboarded, "
        "policy_excluded, never_scanned, runner_offline, or forge_error."
    ),
    "mode": (
        "enforce = gate can fail the check (default). observe = fail_on=none "
        "so findings are reported but cannot block."
    ),
}


def _iso(ts: int | None) -> str | None:
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ts)))


def _load_list_file(path: str) -> list[str]:
    """One repo full_name per line; # comments and blanks ignored."""
    if not path or not os.path.exists(path):
        return []
    out: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # allow "owner/repo" or full github URL tail
            if line.endswith(".git"):
                line = line[:-4]
            if "github.com/" in line:
                line = line.split("github.com/", 1)[1].strip("/")
            out.append(line)
    return out


def _load_excluded(path: str | None = None) -> set[str]:
    path = path or os.environ.get("GATEHOUSE_POLICY_EXCLUDED_REPOS_FILE", "")
    return set(_load_list_file(path))


def _load_org_inventory(path: str | None = None) -> list[str]:
    """Optional full-org repo list so selective App installs cannot hide gaps.

    Without this, known = installation set only (still honest: we only claim
    what the forge App can see). With it, repos in inventory but not installed
    surface as dark reason=not_onboarded.
    """
    path = path or os.environ.get("GATEHOUSE_ORG_INVENTORY_FILE", "")
    return _load_list_file(path)


def mode_for(fail_on: str) -> str:
    """observe only when the gate is explicitly non-blocking."""
    return "observe" if (fail_on or "").strip().lower() in ("none", "off", "disabled") else "enforce"


def classify_repo(
    *,
    full_name: str,
    onboarded: bool,
    excluded: bool,
    last_run: dict | None,
    now: int,
    stale_seconds: int,
    forge_error: str | None = None,
) -> dict:
    """One ledger row. Pure function — unit-tested without GitHub."""
    age = None
    last_at = None
    conclusion = None
    mode = None
    fail_on = None
    pr = None
    if last_run:
        last_at = int(last_run.get("completed_at") or 0) or None
        if last_at:
            age = max(0, now - last_at)
        conclusion = last_run.get("conclusion")
        mode = last_run.get("mode") or mode_for(last_run.get("fail_on") or "")
        fail_on = last_run.get("fail_on") or ""
        pr = last_run.get("pr")

    dark_reason = None
    detail = None
    covered = False

    if forge_error and not onboarded and not last_run:
        dark_reason = DARK_FORGE_ERROR
        detail = forge_error
    elif excluded:
        dark_reason = DARK_POLICY_EXCLUDED
        detail = "Matched policy exclusion list — intentionally not gated"
    elif not onboarded:
        dark_reason = DARK_NOT_ONBOARDED
        detail = "In org inventory but gatehouse App is not installed on this repo"
    elif last_run is None:
        dark_reason = DARK_NEVER_SCANNED
        detail = "App installed; no gate run recorded yet"
    elif age is not None and age > stale_seconds:
        dark_reason = DARK_RUNNER_OFFLINE
        detail = (
            f"Last gate run {age // 3600}h ago (threshold "
            f"{stale_seconds // 3600}h) — runner quiet or webhooks stopped"
        )
    else:
        covered = True
        detail = "Recent gate run within staleness window"

    return {
        "full_name": full_name,
        "onboarded": onboarded,
        "covered": covered,
        "dark_reason": dark_reason,
        "detail": detail,
        "last_gate_run_at": _iso(last_at),
        "last_gate_age_seconds": age,
        "last_conclusion": conclusion,
        "mode": mode,
        "fail_on": fail_on,
        "last_pr": pr,
        "stale": bool(age is not None and age > stale_seconds),
    }


def build_ledger(
    *,
    forge_repos: Iterable[dict],
    gate_runs: dict[str, dict],
    org_inventory: Iterable[str] | None = None,
    excluded: Iterable[str] | None = None,
    now: int | None = None,
    stale_seconds: int = DEFAULT_STALE_SECONDS,
    forge_errors: dict[str, str] | None = None,
    installations: list[dict] | None = None,
) -> dict:
    """Compose the AIM-332 contract body from already-fetched inputs."""
    now = now if now is not None else int(time.time())
    excluded_set = {e.strip() for e in (excluded or []) if e and e.strip()}
    forge_by_name: dict[str, dict] = {}
    for r in forge_repos:
        name = (r.get("full_name") or "").strip()
        if name:
            forge_by_name[name] = r

    names: set[str] = set(forge_by_name)
    names.update(n.strip() for n in (org_inventory or []) if n and n.strip())
    names.update(gate_runs.keys())

    items: list[dict] = []
    for name in sorted(names, key=str.lower):
        row = classify_repo(
            full_name=name,
            onboarded=name in forge_by_name,
            excluded=name in excluded_set,
            last_run=gate_runs.get(name),
            now=now,
            stale_seconds=stale_seconds,
            forge_error=(forge_errors or {}).get(name),
        )
        # Carry forge metadata when present (private/archived) — metadata only.
        meta = forge_by_name.get(name) or {}
        if meta:
            row["private"] = bool(meta.get("private"))
            row["archived"] = bool(meta.get("archived"))
            row["installation_id"] = meta.get("installation_id")
        items.append(row)

    dark_items = [r for r in items if not r["covered"]]
    covered_items = [r for r in items if r["covered"]]
    # Freshest last_gate_run_at for column freshness (whole ledger).
    last_times = [
        int(gate_runs[r["full_name"]]["completed_at"])
        for r in items
        if r["full_name"] in gate_runs and gate_runs[r["full_name"]].get("completed_at")
    ]
    last_event = max(last_times) if last_times else None
    age_seconds = (now - last_event) if last_event else None

    return {
        "as_of": _iso(now),
        "repos_known": len(items),
        "repos_covered": len(covered_items),
        "repos_dark": len(dark_items),
        "stale_threshold_seconds": stale_seconds,
        "freshness": {
            "last_gate_run_at": _iso(last_event),
            "age_seconds": age_seconds,
            "stale": age_seconds is None or age_seconds > stale_seconds,
        },
        "repos": items,
        "dark": [
            {
                "id": r["full_name"],
                "name": r["full_name"],
                "full_name": r["full_name"],
                "reason": r["dark_reason"],
                "detail": r["detail"],
                "last_gate_run_at": r["last_gate_run_at"],
                "last_conclusion": r["last_conclusion"],
                "mode": r["mode"],
                "never_seen": r["dark_reason"] in (DARK_NEVER_SCANNED, DARK_NOT_ONBOARDED),
            }
            for r in dark_items
        ],
        "definitions": DEFINITIONS,
        "installations": installations or [],
        "source": {
            "endpoint": "GET /coverage/repos (gatehouse)",
            "forge": "github_app_installations",
            "org_inventory": "configured" if org_inventory else "not_configured",
            "policy_exclusions": "configured" if excluded_set else "not_configured",
        },
    }


def fetch_forge_repos(client: Client) -> tuple[list[dict], list[dict], dict[str, str]]:
    """Hit the forge API. Returns (repos, installations, errors_by_context)."""
    errors: dict[str, str] = {}
    try:
        installations = client.list_installations()
    except GitHubError as exc:
        log({"event": "gatehouse.coverage.installations_failed",
             "error": str(exc)[:300]})
        raise
    repos: list[dict] = []
    for inst in installations:
        if inst.get("suspended_at"):
            continue
        iid = int(inst.get("id") or 0)
        try:
            repos.extend(client.list_installation_repos(iid))
        except GitHubError as exc:
            msg = str(exc)[:300]
            log({"event": "gatehouse.coverage.repos_failed",
                 "installation_id": iid, "error": msg})
            errors[f"installation:{iid}"] = msg
    return repos, installations, errors


def coverage_report(
    *,
    store: Store,
    client: Client | None = None,
    now: int | None = None,
    stale_seconds: int | None = None,
) -> dict:
    """Full ledger for GET /coverage/repos.

    When the App is not configured (no app id / key), returns a not_wired
    shape so the consumer can render "—" instead of inventing zero.
    """
    stale = stale_seconds if stale_seconds is not None else DEFAULT_STALE_SECONDS
    client = client or Client()
    if not client.app_id or not client.private_key:
        return {
            "state": "not_wired",
            "as_of": _iso(now or int(time.time())),
            "repos_known": None,
            "repos_covered": None,
            "repos_dark": None,
            "not_wired": {
                "endpoint": "GitHub App installations API",
                "awaiting": "GATEHOUSE_APP_ID + GATEHOUSE_PRIVATE_KEY(_FILE)",
                "detail": (
                    "Forge enumeration needs the gatehouse GitHub App credentials. "
                    "Until they are set, the ledger refuses to invent a zero."
                ),
            },
            "definitions": DEFINITIONS,
            "source": {"endpoint": "GET /coverage/repos (gatehouse)"},
        }

    try:
        forge_repos, installations, forge_errors = fetch_forge_repos(client)
    except GitHubError as exc:
        return {
            "state": "error",
            "as_of": _iso(now or int(time.time())),
            "repos_known": None,
            "repos_covered": None,
            "repos_dark": None,
            "error": f"forge enumeration failed: {exc}"[:300],
            "definitions": DEFINITIONS,
            "source": {"endpoint": "GET /coverage/repos (gatehouse)"},
        }

    ledger = build_ledger(
        forge_repos=forge_repos,
        gate_runs=store.latest_gate_runs(),
        org_inventory=_load_org_inventory(),
        excluded=_load_excluded(),
        now=now,
        stale_seconds=stale,
        forge_errors=forge_errors,
        installations=installations,
    )
    ledger["state"] = "ok" if not forge_errors else "partial"
    if forge_errors:
        ledger["forge_errors"] = forge_errors
    return ledger


def dumps(report: dict) -> bytes:
    return json.dumps(report, separators=(",", ":"), sort_keys=False).encode()
