"""The AI review step: bundle -> provider -> validated, anchored findings.

Everything the model says is treated as untrusted output from a text
generator that the PR author can partly steer (the prompt's context is the
PR's own code — prompt injection via PR content is in the threat model). So
the response is validated four ways before anything becomes a `Finding`:

1. **Shape.** Strict JSON, a dict with a `findings` list of dicts. Nothing is
   repaired or guessed; malformed entries are dropped and counted.
2. **Vocabulary.** Unknown severities clamp to `informational`; unknown
   categories fall back to `other`. A real finding with an odd label is kept;
   a finding that claims to be critical must prove it to a human, not to us.
3. **Anchor.** The line must intersect the PR's added ranges for that path
   (`DiffScope.touches`). A finding outside them is the model reviewing code
   the PR did not write — dropped, and counted.
4. **Corroboration.** When the model flags the same lines a deterministic
   scanner already flagged, the scanner finding is the one engineers see: the
   AI copy is dropped and the scanner finding gets `ai_corroborated: "true"`.
   Two tools naming one defect is one row with a stronger signal, not two
   rows — the same rule `dedupe.py` enforces across scanners.

A provider failure is soft: recorded in `stats["error"]`, appended to
`result.errors` by the orchestrator (which renders it as the incomplete-scan
warning and degrades the check to `neutral`), and otherwise invisible to the
conclusion. The LLM endpoint being down must never fail a PR, and must never
look like a clean review either.
"""

from __future__ import annotations

import json
import time

from ..dedupe import _relabel
from ..diffscope import DiffScope
from ..models import Finding, SEVERITY_ID, digest
from . import context, prompt, provider as provider_mod

SCANNER_NAME = "ai-review"

_MAX_TEXT = 300  # model prose is untrusted; cap what we carry around


def _validate(entry: object) -> dict | None:
    """One raw entry -> a sanitized dict, or None when the shape is wrong."""
    if not isinstance(entry, dict):
        return None
    path = entry.get("path")
    line = entry.get("line")
    if not isinstance(path, str) or not path or not isinstance(line, int) or line < 1:
        return None
    end_line = entry.get("end_line")
    if not isinstance(end_line, int) or end_line < line:
        end_line = line
    severity = str(entry.get("severity") or "").lower()
    if severity not in SEVERITY_ID:
        severity = "informational"  # clamp, not drop: the label is wrong, the finding may not be
    category = str(entry.get("category") or "").lower()
    if category not in prompt.CATEGORY_TO_TYPE:
        category = "other"
    return {
        "path": path, "line": line, "end_line": end_line,
        "severity": severity, "category": category,
        "title": str(entry.get("title") or "AI review finding")[:_MAX_TEXT],
        "message": str(entry.get("message") or "")[:_MAX_TEXT * 2],
        "remediation": str(entry.get("remediation") or "")[:_MAX_TEXT],
    }


def _to_finding(valid: dict) -> Finding:
    return Finding(
        scanner=SCANNER_NAME,
        rule_id=f"ai/{valid['category']}",
        finding_type=prompt.CATEGORY_TO_TYPE[valid["category"]],
        title=valid["title"],
        severity=valid["severity"],
        path=valid["path"],
        line=valid["line"],
        end_line=valid["end_line"],
        message=valid["message"],
        remediation=valid["remediation"],
        snippet_digest=digest(f"{valid['title']}|{valid['path']}|{valid['line']}"),
        labels={"category": valid["category"]},
    )


def _overlaps_scanner(ai: Finding, scanner_finding: Finding) -> bool:
    if ai.path != scanner_finding.path:
        return False
    if not ai.line or not scanner_finding.line:  # file-level: same file is enough
        return True
    return ai.line <= scanner_finding.end_line and scanner_finding.line <= ai.end_line


def run(repo_dir: str, scope: DiffScope, *, provider: provider_mod.Provider,
        model: str, scanner_findings: list[Finding],
        max_bytes: int | None = None, context_lines: int | None = None,
        max_graph_bytes: int | None = None, include_graph: bool = True,
        price_in: float = provider_mod.PRICE_USD_PER_1M["default"][0],
        price_out: float = provider_mod.PRICE_USD_PER_1M["default"][1],
        ) -> tuple[list[Finding], list[Finding], dict]:
    """Review one PR's diff. Returns (ai_findings, scanner_findings, stats).

    `scanner_findings` comes back relabeled in place of the input list where
    the model corroborated a scanner result.
    """
    started = time.monotonic()
    stats: dict = {
        "provider": provider.name, "model": model,
        "tokens_in": 0, "tokens_out": 0, "tokens_estimated": False,
        "estimated_cost_usd": 0.0,
        "estimated_cost_without_graph_usd": 0.0,
        "graph_delta_cost_usd": 0.0,
        "duration_ms": 0,
        "parsed": 0, "kept": 0,
        "dropped_invalid": 0, "dropped_unanchored": 0, "dropped_duplicate": 0,
        "error": "",
    }

    kwargs: dict = {"include_graph": include_graph}
    if max_bytes:
        kwargs["max_total_bytes"] = max_bytes
    if context_lines is not None:
        kwargs["context_lines"] = context_lines
    if max_graph_bytes is not None:
        kwargs["max_graph_bytes"] = max_graph_bytes
    bundle, bundle_stats = context.build_bundle(repo_dir, scope, **kwargs)
    stats.update({
        "bundle_bytes": bundle_stats["bytes"],
        "bundle_bytes_without_graph": bundle_stats.get("bytes_without_graph", 0),
        "bundle_files": bundle_stats["files_included"],
        "bundle_skipped": bundle_stats["files_skipped"],
        "bundle_truncated": bundle_stats["truncated_files"],
        "bundle_total_cap_hit": bundle_stats["total_cap_hit"],
        "graph_bytes": bundle_stats.get("graph_bytes", 0),
        "graph_delta_bytes": bundle_stats.get("graph_delta_bytes", 0),
        "graph_delta_tokens": bundle_stats.get("graph_delta_tokens", 0),
        "graph_symbols": bundle_stats.get("graph_symbols", 0),
        "graph_edges": bundle_stats.get("graph_edges", 0),
        "graph_files_indexed": bundle_stats.get("graph_files_indexed", 0),
        "graph_cap_hit": bundle_stats.get("graph_cap_hit", False),
        "graph_enabled": bundle_stats.get("graph_enabled", False),
    })

    if not bundle:
        stats["error"] = ""  # nothing reviewable is not a failure
        stats["duration_ms"] = int((time.monotonic() - started) * 1000)
        return [], scanner_findings, stats

    try:
        raw, usage = provider.review(bundle, model=model)
    except provider_mod.ProviderError as exc:
        stats["error"] = str(exc)[:300]
        stats["duration_ms"] = int((time.monotonic() - started) * 1000)
        return [], scanner_findings, stats

    stats["tokens_in"] = usage.get("tokens_in", 0)
    stats["tokens_out"] = usage.get("tokens_out", 0)
    stats["tokens_estimated"] = bool(usage.get("estimated"))
    stats["estimated_cost_usd"] = provider_mod.estimate_cost(
        stats["tokens_in"], stats["tokens_out"],
        price_in=price_in, price_out=price_out)
    # Cost delta attributable to the graph slice: when the provider reports
    # real tokens, scale the input cost by graph's share of the bundle; when
    # tokens are estimated from bytes, use the byte-delta estimate instead.
    graph_delta_tokens = int(stats.get("graph_delta_tokens") or 0)
    if stats["tokens_in"] and stats.get("bundle_bytes"):
        share = min(1.0, (stats.get("graph_delta_bytes") or 0) / max(1, stats["bundle_bytes"]))
        input_cost = provider_mod.estimate_cost(
            stats["tokens_in"], 0, price_in=price_in, price_out=price_out)
        stats["graph_delta_cost_usd"] = round(input_cost * share, 6)
        stats["estimated_cost_without_graph_usd"] = round(
            stats["estimated_cost_usd"] - stats["graph_delta_cost_usd"], 6)
    elif graph_delta_tokens:
        stats["graph_delta_cost_usd"] = provider_mod.estimate_cost(
            graph_delta_tokens, 0, price_in=price_in, price_out=price_out)
        stats["estimated_cost_without_graph_usd"] = round(
            max(0.0, stats["estimated_cost_usd"] - stats["graph_delta_cost_usd"]), 6)
    else:
        stats["estimated_cost_without_graph_usd"] = stats["estimated_cost_usd"]
        stats["graph_delta_cost_usd"] = 0.0

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # A model that cannot return the documented shape is a provider
        # failure for our purposes — soft, visible, and never blocking.
        stats["error"] = "provider returned non-JSON output"
        stats["duration_ms"] = int((time.monotonic() - started) * 1000)
        return [], scanner_findings, stats
    entries = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        stats["error"] = "provider output has no `findings` list"
        stats["duration_ms"] = int((time.monotonic() - started) * 1000)
        return [], scanner_findings, stats

    stats["parsed"] = len(entries)
    kept: list[Finding] = []
    relabeled = list(scanner_findings)
    for entry in entries:
        valid = _validate(entry)
        if valid is None:
            stats["dropped_invalid"] += 1
            continue
        finding = _to_finding(valid)
        if not scope.touches(finding.path, finding.line, finding.end_line):
            stats["dropped_unanchored"] += 1
            continue
        corroborated = next(
            (i for i, existing in enumerate(relabeled)
             if _overlaps_scanner(finding, existing)), None)
        if corroborated is not None:
            relabeled[corroborated] = _relabel(
                relabeled[corroborated], ai_corroborated="true")
            stats["dropped_duplicate"] += 1
            continue
        kept.append(finding)

    stats["kept"] = len(kept)
    stats["duration_ms"] = int((time.monotonic() - started) * 1000)
    return kept, relabeled, stats
