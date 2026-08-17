"""semgrep — SAST over the files this PR changed.

**Rules are vendored, not fetched.** `--config auto` (and the `p/…` registry
packs) resolve over the network at scan time, which would mean a security gate
whose behaviour changes without a commit, an outbound dependency on every scan,
and a supply-chain path straight into a service that has the customer's source
tree on disk. `rules/semgrep/` in this repo is the ruleset (injection, authz,
crypto, deserialization; ai_llm + ssrf depth —): reviewable
in a PR, pinned by commit, and it works air-gapped (D6 ships on one VM,
possibly with no egress). Adding a rule is a YAML edit under that directory,
not a scanner/runner code change.
`GATEHOUSE_SEMGREP_CONFIG` can point at registry packs for anyone who accepts
that trade; the default does not.

Each vendored rule declares `metadata.gatehouse_type`, which becomes the alert
contract's `finding_type` suffix. Rules from elsewhere degrade to
`sast_issue` with the CWE preserved as a label rather than being dropped.
"""

from __future__ import annotations

import json
import os
import re

from .. import severity as sev
from ..models import Finding, digest
from .base import ScanOutcome, read_line, run_tool, timed

DEFAULT_RULES = os.environ.get(
    "GATEHOUSE_SEMGREP_CONFIG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules", "semgrep"),
)
_SUFFIX_SAFE = re.compile(r"[^a-z0-9_]")
_CWE = re.compile(r"CWE-\d+")


def finding_type(metadata: dict) -> str:
    """`pr_security.<subtype>` — the contract requires exactly one dot (§3.1)."""
    raw = str(metadata.get("gatehouse_type") or "sast_issue").lower()
    return f"pr_security.{_SUFFIX_SAFE.sub('_', raw)[:40] or 'sast_issue'}"


@timed("semgrep")
def scan(repo_dir: str, paths: list[str], *, config: str | None = None) -> ScanOutcome:
    outcome = ScanOutcome("semgrep")
    if not paths:
        outcome.skipped = True
        return outcome

    rules = config or DEFAULT_RULES
    argv = ["semgrep", "scan", "--json", "--quiet", "--metrics=off",
            "--disable-version-check", "--config", rules, "--", *paths]
    run = run_tool(argv, cwd=repo_dir)
    if run.error:
        outcome.error = run.error
        return outcome
    try:
        report = json.loads(run.stdout or "{}")
    except json.JSONDecodeError as exc:
        outcome.error = f"semgrep output unparseable: {exc}"
        return outcome

    # semgrep reports per-file failures (a parse error, an unreadable file) in
    # `errors` while still exiting 0. Left unread, a file that semgrep could
    # not parse would be indistinguishable from a clean one.
    blocking = [e for e in report.get("errors", []) if e.get("level") != "warn"]
    if blocking:
        outcome.error = "; ".join(
            str(e.get("message", "semgrep error"))[:120] for e in blocking[:3])

    for item in report.get("results", []):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        path = (item.get("path") or "").replace("\\", "/")
        line = int((item.get("start") or {}).get("line") or 0)
        end_line = int((item.get("end") or {}).get("line") or line)
        # semgrep namespaces `check_id` with the *filesystem path* the rules
        # were loaded from, so a local ruleset produces ids like
        # `tmp.w.services.gatehouse.….injection.python-sql-injection-format`.
        # That path is an artifact of where the container mounted the rules; it
        # would end up in the dedupe key, so every finding's identity would
        # rotate the day the image layout changed, and the whole inbox would
        # re-alert. The last segment is the rule's actual name.
        rule_id = str(item.get("check_id") or "semgrep-rule").rsplit(".", 1)[-1]
        labels = {"rule": rule_id[:64]}
        cwe = _CWE.search(str(metadata.get("cwe") or ""))
        if cwe:
            labels["cwe"] = cwe.group(0)
        outcome.findings.append(Finding(
            scanner="semgrep",
            rule_id=rule_id,
            finding_type=finding_type(metadata),
            title=str(metadata.get("short_description")
                      or extra.get("message") or rule_id).strip().split("\n")[0][:200],
            severity=sev.from_semgrep(extra.get("severity")),
            path=path,
            line=line,
            end_line=end_line,
            message=str(extra.get("message") or "").strip()[:600],
            remediation=str(metadata.get("remediation") or "").strip()[:500],
            # `extra.lines` is the matched source. Hashed for identity so the
            # finding survives a re-push that moves the code, then discarded.
            snippet_digest=digest(extra.get("lines") or read_line(repo_dir, path, line)
                                  or f"{path}:{rule_id}"),
            labels=labels,
        ))
    return outcome
