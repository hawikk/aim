#!/usr/bin/env python3
"""CI health rates for security-gate workflows (AIM-444).

Why this exists
---------------
A cancelled security gate is not a pass, but it is easy to read as "not red"
when browsing the PR check list. Mass cancellation (concurrency + saturated
runners) made that the modal outcome: 62–72% of trailing ``ci.yml`` runs ended
``cancelled``. This report makes success / cancelled / failure / queued rates
visible **without** opening the Actions tab:

  * sticky GitHub issue body (Issues list / search)
  * ``$GITHUB_STEP_SUMMARY`` when run in Actions
  * optional JSON file for bus/dashboards

Exit codes
----------
  0  — rates computed; cancelled rate at or below threshold
  1  — usage / API / parse error (fail closed — cannot claim health)
  2  — cancelled rate above ``--max-cancelled`` (loud regression)

Usage
-----
  # from a pre-fetched run list (tests / offline)
  python3 scripts/ci_health_report.py --runs-json runs.json

  # live via gh
  python3 scripts/ci_health_report.py --repo hawikk/aim --limit 50

  # CI / ops: write sticky issue + step summary, fail if cancelled > 10%
  python3 scripts/ci_health_report.py --repo hawikk/aim \\
      --limit 50 --max-cancelled 0.10 --update-issue --markdown-out report.md

  python3 scripts/ci_health_report.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_WORKFLOW = "ci.yml"
DEFAULT_LIMIT = 50
DEFAULT_MAX_CANCELLED = 0.10
STICKY_TITLE = "[CI Health] trailing run rates (AIM-444)"
ISSUE_MARKER = "<!-- aim-ci-health-report -->"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_run(run: dict[str, Any]) -> str:
    """Map a workflow run to a single health bucket.

    Terminal conclusions win. In-flight runs (queued / in_progress / waiting /
    pending / requested) land in ``queued`` so the report surfaces backlog
    without opening Actions.
    """
    status = (run.get("status") or "").lower()
    conclusion = (run.get("conclusion") or "").lower()

    if status and status not in ("completed", ""):
        # GitHub uses queued / in_progress / waiting / requested / pending.
        if status in ("queued", "waiting", "pending", "requested", "in_progress"):
            return "queued"
        return status

    if not conclusion:
        return "unknown"

    if conclusion in ("cancelled", "canceled"):
        return "cancelled"
    if conclusion == "success":
        return "success"
    if conclusion == "failure":
        return "failure"
    if conclusion in ("skipped", "neutral", "timed_out", "action_required", "stale"):
        return conclusion
    return conclusion


def summarize_runs(
    runs: list[dict[str, Any]],
    *,
    workflow: str,
    repo: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    buckets = Counter(classify_run(r) for r in runs)
    n = len(runs)
    rates = {k: (v / n if n else 0.0) for k, v in buckets.items()}
    # Always surface the headline buckets even when zero.
    for key in ("success", "cancelled", "failure", "queued"):
        rates.setdefault(key, 0.0)
        buckets.setdefault(key, 0)

    completed = [r for r in runs if (r.get("status") or "").lower() == "completed"]
    completed_n = len(completed)
    completed_cancelled = sum(
        1 for r in completed if classify_run(r) == "cancelled"
    )
    completed_cancelled_rate = (
        completed_cancelled / completed_n if completed_n else 0.0
    )

    return {
        "generatedAt": generated_at or _utc_now(),
        "repo": repo,
        "workflow": workflow,
        "limit": n,
        "counts": dict(buckets),
        "rates": rates,
        "completed": {
            "n": completed_n,
            "cancelled": completed_cancelled,
            "cancelledRate": completed_cancelled_rate,
        },
        "source": "ci_health_report.py",
        "aim": "AIM-444",
    }


def format_markdown(report: dict[str, Any], *, max_cancelled: float) -> str:
    counts = report["counts"]
    rates = report["rates"]
    n = report["limit"]
    completed = report["completed"]
    cancelled_rate = rates.get("cancelled", 0.0)
    status = "OK" if cancelled_rate <= max_cancelled else "REGRESSION"
    lines = [
        ISSUE_MARKER,
        f"# CI health — `{report['workflow']}`",
        "",
        f"**Status:** {status}  ",
        f"**Repo:** `{report['repo']}`  ",
        f"**Generated:** {report['generatedAt']}  ",
        f"**Window:** trailing {n} workflow runs  ",
        f"**Threshold:** cancelled ≤ {max_cancelled:.0%}  ",
        "",
        "## Rates (open this issue — do not open the Actions tab)",
        "",
        "| Bucket | Count | Rate |",
        "| --- | ---: | ---: |",
    ]
    order = ["success", "cancelled", "failure", "queued"]
    seen = set(order)
    for key in order:
        lines.append(
            f"| `{key}` | {counts.get(key, 0)} | {rates.get(key, 0.0):.1%} |"
        )
    for key in sorted(counts):
        if key in seen:
            continue
        lines.append(f"| `{key}` | {counts[key]} | {rates[key]:.1%} |")

    lines += [
        "",
        "## Completed-only cancelled rate",
        "",
        f"Among **{completed['n']}** completed runs, "
        f"**{completed['cancelled']}** ended `cancelled` "
        f"({completed['cancelledRate']:.1%}).",
        "",
        "## Why cancelled is not neutral",
        "",
        "Auto-merge and merge-audit treat a cancelled required check as "
        "**not satisfied** (same as failed / missing / skipped).",
        "",
        "## Control",
        "",
        "- Security-gate workflow (`ci.yml`) must **not** use workflow-level "
        "`concurrency` with cancel-in-progress (AIM-444 / AIM-411).",
        "- `release-images.yml` may keep cancel-in-progress (redundant builds).",
        "- Re-run: `python3 scripts/ci_health_report.py --repo "
        f"{report['repo']} --limit {n}`",
        "",
        f"_Source: `{report['source']}` · {report['aim']}_",
        "",
    ]
    return "\n".join(lines)


def load_runs_json(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("workflow_runs"), list):
        return data["workflow_runs"]
    raise ValueError(f"{path}: expected a JSON list of runs or {{workflow_runs: [...]}}")


def fetch_runs_via_gh(repo: str, workflow: str, limit: int) -> list[dict[str, Any]]:
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    env["CLICOLOR"] = "0"
    env["GH_PAGER"] = "cat"
    env.pop("FORCE_COLOR", None)
    env.pop("CLICOLOR_FORCE", None)
    cmd = [
        "gh",
        "run",
        "list",
        f"--repo={repo}",
        f"--workflow={workflow}",
        f"--limit={limit}",
        "--json",
        "conclusion,status,event,createdAt,displayTitle,databaseId,headBranch,headSha",
    ]
    try:
        proc = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
    except FileNotFoundError as e:
        raise RuntimeError("gh not found in PATH; pass --runs-json or install gh") from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"gh run list failed (exit {e.returncode}): {e.stderr or e.stdout}"
        ) from e
    return json.loads(proc.stdout)


def fetch_runs_via_api(
    repo: str, workflow: str, limit: int, token: str
) -> list[dict[str, Any]]:
    """List workflow runs without `gh` (GITHUB_TOKEN in Actions)."""
    # Resolve workflow file → id, then list runs.
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "aim-ci-health-report",
    }
    wf_url = (
        f"https://api.github.com/repos/{repo}/actions/workflows/{workflow}/runs"
        f"?per_page={min(limit, 100)}"
    )
    req = urllib.request.Request(wf_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API {e.code} for {wf_url}: {detail}") from e
    runs = body.get("workflow_runs") or []
    return runs[:limit]


def _strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s or "")


def _gh_env() -> dict[str, str]:
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    env["CLICOLOR"] = "0"
    env["GH_PAGER"] = "cat"
    env.pop("FORCE_COLOR", None)
    env.pop("CLICOLOR_FORCE", None)
    return env


def _gh_json(args: list[str]) -> Any:
    proc = subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        env=_gh_env(),
    )
    raw = _strip_ansi(proc.stdout).strip()
    if not raw:
        raise RuntimeError(
            f"gh returned empty stdout for: {' '.join(args)}\nstderr={proc.stderr}"
        )
    return json.loads(raw)


def upsert_sticky_issue(
    repo: str,
    body: str,
    *,
    token: str | None,
) -> dict[str, Any]:
    """Create or update the sticky CI health issue. Returns {number, url, action}."""
    owner, name = repo.split("/", 1)

    def api(
        method: str, path: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any] | list[Any]:
        url = f"https://api.github.com{path}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "aim-ci-health-report",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API {e.code} {method} {path}: {detail}") from e

    # Prefer token path; fall back to gh if no token.
    if not token:
        import tempfile

        issues = _gh_json(
            [
                "gh",
                "issue",
                "list",
                f"--repo={repo}",
                "--state",
                "open",
                "--limit",
                "100",
                "--json",
                "number,title,url",
            ]
        )
        match = next((i for i in issues if i.get("title") == STICKY_TITLE), None)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=".md", delete=False
        ) as tf:
            tf.write(body)
            body_path = tf.name
        try:
            if match:
                subprocess.run(
                    [
                        "gh",
                        "issue",
                        "edit",
                        str(match["number"]),
                        f"--repo={repo}",
                        "--body-file",
                        body_path,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    env=_gh_env(),
                )
                return {
                    "number": match["number"],
                    "url": match["url"],
                    "action": "updated",
                }
            proc = subprocess.run(
                [
                    "gh",
                    "issue",
                    "create",
                    f"--repo={repo}",
                    "--title",
                    STICKY_TITLE,
                    "--body-file",
                    body_path,
                ],
                check=True,
                capture_output=True,
                text=True,
                env=_gh_env(),
            )
            url = _strip_ansi(proc.stdout or "").strip()
            number = int(url.rstrip("/").split("/")[-1]) if url else 0
            return {"number": number, "url": url, "action": "created"}
        finally:
            try:
                os.unlink(body_path)
            except OSError:
                pass

    # Token path: list open issues and match title.
    issues = api(
        "GET",
        f"/repos/{owner}/{name}/issues?state=open&per_page=100",
    )
    assert isinstance(issues, list)
    match = next(
        (
            i
            for i in issues
            if isinstance(i, dict)
            and i.get("title") == STICKY_TITLE
            and "pull_request" not in i
        ),
        None,
    )
    if match:
        api(
            "PATCH",
            f"/repos/{owner}/{name}/issues/{match['number']}",
            {"body": body},
        )
        return {
            "number": match["number"],
            "url": match.get("html_url") or match.get("url"),
            "action": "updated",
        }
    # No labels: unknown label names 422 and would silence the health report.
    created = api(
        "POST",
        f"/repos/{owner}/{name}/issues",
        {
            "title": STICKY_TITLE,
            "body": body,
        },
    )
    assert isinstance(created, dict)
    return {
        "number": created.get("number"),
        "url": created.get("html_url") or created.get("url"),
        "action": "created",
    }


def self_test() -> None:
    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            failures.append(msg)

    # classify
    check(classify_run({"status": "completed", "conclusion": "cancelled"}) == "cancelled", "cancelled")
    check(classify_run({"status": "completed", "conclusion": "canceled"}) == "cancelled", "canceled spelling")
    check(classify_run({"status": "completed", "conclusion": "success"}) == "success", "success")
    check(classify_run({"status": "queued", "conclusion": ""}) == "queued", "queued status")
    check(classify_run({"status": "in_progress", "conclusion": None}) == "queued", "in_progress bucketed as queued")
    check(classify_run({"status": "completed", "conclusion": "failure"}) == "failure", "failure")

    # summarize rates
    runs = [
        {"status": "completed", "conclusion": "success"},
        {"status": "completed", "conclusion": "cancelled"},
        {"status": "completed", "conclusion": "cancelled"},
        {"status": "completed", "conclusion": "failure"},
        {"status": "queued", "conclusion": ""},
    ]
    report = summarize_runs(runs, workflow="ci.yml", repo="o/r", generated_at="T0")
    check(report["limit"] == 5, "limit")
    check(report["counts"]["cancelled"] == 2, "cancelled count")
    check(abs(report["rates"]["cancelled"] - 0.4) < 1e-9, "cancelled rate 2/5")
    check(report["counts"]["queued"] == 1, "queued count")
    check(report["completed"]["n"] == 4, "completed n")
    check(abs(report["completed"]["cancelledRate"] - 0.5) < 1e-9, "completed cancelled 2/4")

    md = format_markdown(report, max_cancelled=0.10)
    check(ISSUE_MARKER in md, "marker in markdown")
    check("REGRESSION" in md, "above threshold is REGRESSION")
    check("`cancelled`" in md and "40.0%" in md, "cancelled rate rendered")

    ok_report = summarize_runs(
        [{"status": "completed", "conclusion": "success"}] * 10,
        workflow="ci.yml",
        repo="o/r",
    )
    ok_md = format_markdown(ok_report, max_cancelled=0.10)
    check("**Status:** OK" in ok_md, "all-success is OK")

    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        sys.exit(1)
    print("ci_health_report.py self-test: OK")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", default=os.environ.get("GH_REPO", "hawikk/aim"))
    p.add_argument("--workflow", default=DEFAULT_WORKFLOW)
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    p.add_argument(
        "--max-cancelled",
        type=float,
        default=DEFAULT_MAX_CANCELLED,
        help="fail with exit 2 when cancelled rate exceeds this fraction (default 0.10)",
    )
    p.add_argument("--runs-json", type=Path, help="use a local runs JSON instead of the API")
    p.add_argument("--json-out", type=Path, help="write full report JSON")
    p.add_argument("--markdown-out", type=Path, help="write markdown report")
    p.add_argument(
        "--update-issue",
        action="store_true",
        help="create/update the sticky GitHub issue with the markdown body",
    )
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""

    try:
        if args.runs_json:
            runs = load_runs_json(args.runs_json)
        elif token and not shutil_which("gh"):
            runs = fetch_runs_via_api(args.repo, args.workflow, args.limit, token)
        else:
            try:
                runs = fetch_runs_via_gh(args.repo, args.workflow, args.limit)
            except RuntimeError:
                if not token:
                    raise
                runs = fetch_runs_via_api(args.repo, args.workflow, args.limit, token)
    except Exception as e:
        print(f"[ci-health] ERROR: {e}", file=sys.stderr)
        return 1

    # Trim if caller passed a larger dump.
    runs = runs[: args.limit]
    report = summarize_runs(runs, workflow=args.workflow, repo=args.repo)
    md = format_markdown(report, max_cancelled=args.max_cancelled)

    print(
        f"[ci-health] {args.repo} {args.workflow} n={report['limit']} "
        f"success={report['rates']['success']:.1%} "
        f"cancelled={report['rates']['cancelled']:.1%} "
        f"failure={report['rates']['failure']:.1%} "
        f"queued={report['rates']['queued']:.1%}"
    )
    print(md)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"[ci-health] wrote {args.json_out}")

    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(md, encoding="utf-8")
        print(f"[ci-health] wrote {args.markdown_out}")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as f:
            f.write(md)
            f.write("\n")

    if args.update_issue:
        try:
            meta = upsert_sticky_issue(args.repo, md, token=token or None)
            print(
                f"[ci-health] sticky issue {meta['action']}: "
                f"#{meta['number']} {meta['url']}"
            )
            report["issue"] = meta
            if args.json_out:
                args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except Exception as e:
            print(f"[ci-health] ERROR updating sticky issue: {e}", file=sys.stderr)
            return 1

    cancelled_rate = report["rates"].get("cancelled", 0.0)
    if cancelled_rate > args.max_cancelled:
        print(
            f"::error title=CI cancelled-rate regression::"
            f"cancelled rate {cancelled_rate:.1%} exceeds max {args.max_cancelled:.0%} "
            f"over trailing {report['limit']} {args.workflow} runs (AIM-444)",
            file=sys.stderr,
        )
        return 2
    return 0


def shutil_which(cmd: str) -> str | None:
    from shutil import which

    return which(cmd)


if __name__ == "__main__":
    sys.exit(main())
