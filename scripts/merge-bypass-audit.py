#!/usr/bin/env python3
"""Audit the last N merges: did every required gate execute and pass?

Honest numbers. For each merged PR:

* re-derive required checks from `.github/required-checks.json` + PR files
* look up the latest check-run per name on the PR head SHA
* classify: clean | unauthorized_bypass | deliberate_bypass

Writes machine-readable JSON and optional markdown report. Also records each
row into the gatehouse evidence store when importable (90-day retention).

Usage:
  python3 scripts/merge-bypass-audit.py
  python3 scripts/merge-bypass-audit.py --limit 30 --markdown docs/security/aim-446-bypass-audit.md
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPO = os.environ.get("AIM446_REPO", "hawikk/ai-monitoring")


def run(args: list[str]) -> str:
    env = {
        **os.environ,
        "NO_COLOR": "1",
        "CLICOLOR": "0",
        "TERM": "dumb",
        "GH_FORCE_TTY": "0",
    }
    return subprocess.check_output(args, text=True, env=env)


def gh_json(args: list[str]):
    return json.loads(run(["gh"] + args))


def matches(file: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        return file.startswith(pattern)
    if any(ch in pattern for ch in "*?"):
        parts = pattern.split("**")
        rx = ".*".join(
            re.escape(p).replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
            for p in parts
        )
        return re.fullmatch(rx, file) is not None
    return file == pattern or file.startswith(pattern + "/")


def required_for(cfg: dict, files: list[str]) -> list[str]:
    out = list(cfg.get("always") or [])
    for c in cfg.get("conditional") or []:
        when = c.get("when_paths_changed") or []
        if any(matches(f, p) for f in files for p in when):
            name = c.get("check")
            if name and name not in out:
                out.append(name)
    return out


def latest_checks(repo: str, sha: str) -> dict[str, dict]:
    data = gh_json(["api", f"repos/{repo}/commits/{sha}/check-runs", "--paginate"])
    runs = []
    if isinstance(data, dict):
        runs = data.get("check_runs") or []
    elif isinstance(data, list):
        for page in data:
            if isinstance(page, dict):
                runs.extend(page.get("check_runs") or [])
    out: dict[str, dict] = {}
    for r in runs:
        name = r.get("name")
        if not name:
            continue
        prev = out.get(name)
        if not prev or (r.get("id") or 0) > (prev.get("id") or 0):
            out[name] = r
    return out


def classify_row(required: list[str], checks: dict[str, dict], labels: list[str]) -> dict:
    missing, failed, green = [], [], []
    verdicts = {}
    for name in required:
        c = checks.get(name)
        if not c:
            missing.append(name)
            verdicts[name] = {"state": "ABSENT"}
            continue
        state = c.get("conclusion") or c.get("status") or "unknown"
        entry = {
            "state": state,
            "status": c.get("status"),
            "conclusion": c.get("conclusion"),
            "check_run_id": c.get("id"),
            "html_url": c.get("html_url"),
            "completed_at": c.get("completed_at"),
        }
        verdicts[name] = entry
        if c.get("status") == "completed" and c.get("conclusion") == "success":
            green.append(name)
        else:
            failed.append(f"{name}={state}")
    bypass = bool(missing or failed)
    deliberate = "security-bypass" in labels
    if not bypass:
        classification = "clean"
    elif deliberate:
        classification = "deliberate_bypass"
    else:
        classification = "unauthorized_bypass"
    return {
        "missing": missing,
        "failed": failed,
        "green": green,
        "verdicts": verdicts,
        "bypass": bypass,
        "deliberate_bypass": deliberate and bypass,
        "unauthorized_bypass": bypass and not deliberate,
        "classification": classification,
    }


def record_evidence(rows: list[dict], *, repo: str) -> int:
    try:
        sys.path.insert(0, str(ROOT / "services" / "gatehouse" / "src"))
        from gatehouse import evidence as evidence_mod  # type: ignore

        store = evidence_mod.EvidenceStore()
        n = 0
        try:
            for row in rows:
                verdicts = []
                for name, v in (row.get("verdicts") or {}).items():
                    verdicts.append(evidence_mod.GateVerdict(
                        name=name,
                        required=True,
                        status=v.get("status"),
                        conclusion=v.get("conclusion"),
                        check_run_id=v.get("check_run_id"),
                        html_url=v.get("html_url"),
                        completed_at=v.get("completed_at"),
                    ))
                store.put(evidence_mod.GateEvidence(
                    repo=repo,
                    head_sha=row["head_sha"],
                    pr_number=row["pr"],
                    merge_sha=row.get("merge_sha"),
                    actor=row.get("author"),
                    merged_at=row.get("mergedAt"),
                    classification=row["classification"],
                    notes=[
                        "Merge bypass audit",
                        f"green={row['green_count']}/{row['required_count']}",
                    ],
                    verdicts=verdicts,
                    scanner_output={
                        "source": "aim-446-merge-bypass-audit",
                        "missing": row.get("missing"),
                        "failed": row.get("failed"),
                    },
                ))
                n += 1
        finally:
            store.close()
        return n
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"event": "audit.evidence_write_failed",
                          "error": str(exc)[:200]}), file=sys.stderr)
        return 0


def to_markdown(payload: dict) -> str:
    s = payload["summary"]
    lines = [
        "# merge bypass audit — last "
        f"{s['limit']} merges\n",
        f"**Repo:** `{s['repo']}`  \n"
        f"**Generated:** `{payload['generated_at']}`  \n"
        f"**Required always checks:** {len(s['required_always'])}\n",
        "## Summary (honest numbers)\n",
        f"| Class | Count |\n|---|---:|\n"
        f"| Total merges audited | {s['total']} |\n"
        f"| Clean (every required gate green) | **{s['clean']}** |\n"
        f"| Unauthorized bypass | **{s['unauthorized_bypass']}** |\n"
        f"| Deliberate bypass (`security-bypass` + reason) | {s['deliberate_bypass']} |\n",
        f"**Bypass rate:** "
        f"{(s['unauthorized_bypass'] + s['deliberate_bypass']) / max(1, s['total']):.0%} "
        f"({s['unauthorized_bypass'] + s['deliberate_bypass']}/{s['total']}). "
        f"Unauthorized only: "
        f"{s['unauthorized_bypass'] / max(1, s['total']):.0%}.\n",
        "## What this means\n",
        "Branch protection / rulesets are **403** on this plan, so a human or\n"
        "agent can still run `gh pr merge` while required checks are red or\n"
        "queued. The fail-closed `auto-merge` path refuses red checks; the\n"
        "out-of-band `gatehouse merge-audit` detects after the fact. This\n"
        "table is the on-demand proof of how often merges actually landed\n"
        "without every required gate green.\n",
        "## Per-merge table\n",
        "| PR | Merged | Class | Green | Missing/Failed | Head |\n"
        "|---:|---|---|---:|---|---|\n",
    ]
    for r in payload["rows"]:
        bad = ", ".join(r["missing"] + r["failed"]) or "—"
        if len(bad) > 80:
            bad = bad[:77] + "…"
        lines.append(
            f"| [#{r['pr']}]({r['url']}) | {r['mergedAt'][:10]} | "
            f"`{r['classification']}` | {r['green_count']}/{r['required_count']} | "
            f"{bad} | `{r['head_sha'][:10]}` |\n"
        )
    lines.append("\n## Required always checks\n\n")
    for name in s["required_always"]:
        lines.append(f"- `{name}`\n")
    lines.append(
        "\n## Method\n\n"
        "1. `gh pr list --state merged --limit N`\n"
        "2. For each PR head SHA: `GET /repos/.../commits/{sha}/check-runs`\n"
        "3. Required set = `always` ∪ conditional matches on PR files\n"
        "4. Green ⇔ `status=completed` and `conclusion=success`\n"
        "5. Deliberate ⇔ PR has label `security-bypass`\n"
        "\nEvidence rows also written to `gatehouse evidence` (90-day retention)\n"
        "when the package is importable.\n"
        "\nRegenerate:\n\n"
        "```bash\n"
        "python3 scripts/merge-bypass-audit.py --limit 30 \\\n"
        "  --markdown docs/security/aim-446-bypass-audit.md \\\n"
        "  --json docs/security/aim-446-bypass-audit.json\n"
        "```\n"
    )
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--gate", default=str(ROOT / ".github" / "required-checks.json"))
    ap.add_argument("--json", default="", help="write full JSON report here")
    ap.add_argument("--markdown", default="", help="write markdown report here")
    ap.add_argument("--no-evidence", action="store_true")
    args = ap.parse_args(argv)

    repo = args.repo
    cfg = json.loads(Path(args.gate).read_text())
    always = list(cfg.get("always") or [])

    prs = gh_json([
        "pr", "list", "--repo", repo, "--state", "merged",
        "--limit", str(args.limit),
        "--json", "number,title,mergedAt,mergeCommit,url,labels,author",
    ])
    prs.sort(key=lambda p: p.get("mergedAt") or "", reverse=True)

    rows = []
    for pr in prs:
        num = pr["number"]
        detail = gh_json([
            "pr", "view", str(num), "--repo", repo,
            "--json", "commits,labels,mergeCommit,files",
        ])
        commits = detail.get("commits") or []
        head_sha = commits[-1]["oid"] if commits else None
        merge_sha = (detail.get("mergeCommit") or pr.get("mergeCommit") or {}).get("oid")
        labels = [l["name"] for l in (detail.get("labels") or [])]
        files = [f["path"] for f in (detail.get("files") or [])]
        required = required_for(cfg, files)
        checks = latest_checks(repo, head_sha) if head_sha else {}
        graded = classify_row(required, checks, labels)
        row = {
            "pr": num,
            "title": pr.get("title"),
            "url": pr.get("url"),
            "mergedAt": pr.get("mergedAt"),
            "author": (pr.get("author") or {}).get("login"),
            "head_sha": head_sha,
            "merge_sha": merge_sha,
            "labels": labels,
            "required_count": len(required),
            "green_count": len(graded["green"]),
            "missing": graded["missing"],
            "failed": graded["failed"],
            "verdicts": graded["verdicts"],
            "classification": graded["classification"],
            "bypass": graded["bypass"],
            "deliberate_bypass": graded["deliberate_bypass"],
            "unauthorized_bypass": graded["unauthorized_bypass"],
        }
        rows.append(row)
        print(
            f"PR #{num:>4} {row['classification']:20} "
            f"green={row['green_count']:2}/{row['required_count']:2} "
            f"sha={(head_sha or '')[:10]}  {(pr.get('title') or '')[:55]}",
            flush=True,
        )

    summary = {
        "total": len(rows),
        "clean": sum(1 for r in rows if r["classification"] == "clean"),
        "unauthorized_bypass": sum(
            1 for r in rows if r["classification"] == "unauthorized_bypass"
        ),
        "deliberate_bypass": sum(
            1 for r in rows if r["classification"] == "deliberate_bypass"
        ),
        "required_always": always,
        "repo": repo,
        "limit": args.limit,
    }
    payload = {
        "kind": "aim-446-merge-bypass-audit",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": summary,
        "rows": rows,
    }

    if not args.no_evidence:
        n = record_evidence(rows, repo=repo)
        payload["evidence_rows_written"] = n

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n")
        print("wrote", args.json)
    if args.markdown:
        Path(args.markdown).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown).write_text(to_markdown(payload))
        print("wrote", args.markdown)

    print("---")
    print(json.dumps(summary, indent=2))
    # Non-zero when any unauthorized bypass exists — the control is loud.
    return 1 if summary["unauthorized_bypass"] else 0


if __name__ == "__main__":
    sys.exit(main())
