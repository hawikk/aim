#!/usr/bin/env python3
"""Enforcement bake driver.

Runs the *shipped* endpoint enforcement decision engine (collectors/claude-code
``aim_collector.enforce`` + ``matchers``) over the real Claude Code transcripts
on a pilot/dogfood endpoint, in shadow mode, and emits the resulting audit
events through the real collector pipeline (spool -> ingest -> events table)
so ``scripts/shadow-report.mjs`` aggregates them.

Why a backtest and not only live-hook capture: shipped the hooks,
but the fleet had no delivered enforcement bundle, so the live report showed 0
events (docs/aim-110-shadow-report-2026-07-22.md). This driver closes the
credibility gap now by scoring *real developer activity already on the
endpoint* with the exact shipped rules, while the live hooks (installed by
this same change) begin the forward-looking 2-week quiet-telemetry window.

Honesty contract:
  - Uses the shipped decision functions verbatim (no reimplemented rules).
  - Metadata-only, fail-open posture unchanged: only action + rule_id +
    policy_hash leave a machine; matched content is scanned in memory and
    discarded (same as personal mode).
  - Events are dated at their real transcript activity time so the per-day
    would-block distribution and sessions/day baseline are truthful.
  - Deterministic event_ids (uuid5) make re-runs idempotent (ingest dedupes
    on event_id), so the bake can be re-run without double counting.

Usage:
  python scripts/shadow-bake.py [--since-days N] [--dry-run]

Env:
  AIM_ENFORCEMENT_FILE  shadow policy bundle (required; the driver refuses to
                        run against a live 'enforce' bundle).
  AIM_INGEST_URL / AIM_COLLECTOR_TOKEN  ingestion target (else config file).
  AIM_CLAUDE_PROJECTS_DIR  transcript root (default ~/.claude/projects).
"""
import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collectors" / "claude-code"))

from aim_collector import enforce, events, matchers, spool, state  # noqa: E402

# Stable namespace so re-runs produce identical event_ids (idempotent ingest).
_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "aim-117-shadow-bake.ai-monitoring")


def _iso_day(ts: str | None) -> str | None:
    if not isinstance(ts, str):
        return None
    try:
        return ts.replace("Z", "+00:00")
    except Exception:
        return None


def _prompt_text(msg: dict) -> str | None:
    """Human/agent-authored prompt text a UserPromptSubmit hook would see.
    Skips tool_result blocks (those are not a prompt submission)."""
    content = msg.get("content")
    if isinstance(content, str):
        return content or None
    if not isinstance(content, list):
        return None
    parts = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            t = block.get("text")
            if isinstance(t, str) and t:
                parts.append(t)
    return "\n".join(parts) if parts else None


def _det_id(*key) -> str:
    return str(uuid.uuid5(_NS, "|".join(str(k) for k in key)))


def _finalize(ev: dict, event_id: str) -> dict:
    ev["event_id"] = event_id
    return ev


def run(since_days: int, dry_run: bool) -> dict:
    pol = enforce.load_policy()
    if not pol:
        raise SystemExit("no enforcement policy resolved (set AIM_ENFORCEMENT_FILE)")
    if pol.get("mode") == "enforce":
        raise SystemExit("refusing to bake against a live 'enforce' bundle — shadow only")

    root = Path(os.environ.get("AIM_CLAUDE_PROJECTS_DIR",
                               "~/.claude/projects")).expanduser()
    files = sorted(root.glob("**/*.jsonl"))
    cutoff = datetime.now(timezone.utc).timestamp() - since_days * 86400

    out: list[dict] = []
    stats = {
        "transcripts_scanned": 0, "sessions": 0, "prompts_scanned": 0,
        "tool_calls_scanned": 0, "mcp_calls": 0,
        "would_block": {}, "sessions_by_day": {}, "first_ts": None,
        "last_ts": None, "mcp_servers_seen": {},
        "mcp_discovery_would_block": 0,  # sensitivity: MCP rule with empty inventory
    }

    def bump(d, k, n=1):
        d[k] = d.get(k, 0) + n

    for path in files:
        try:
            if path.stat().st_mtime < cutoff:
                continue
        except OSError:
            continue
        raw_session_id = path.stem
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        session_seen = False
        last_activity = None
        cwd = None
        tokens_in = tokens_out = 0
        model = None

        for idx, line in enumerate(lines):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = rec.get("message") if isinstance(rec.get("message"), dict) else rec
            ts = rec.get("timestamp")
            if isinstance(ts, str):
                last_activity = ts if (last_activity is None or ts > last_activity) else last_activity
                if stats["first_ts"] is None or ts < stats["first_ts"]:
                    stats["first_ts"] = ts
                if stats["last_ts"] is None or ts > stats["last_ts"]:
                    stats["last_ts"] = ts
            if not cwd and isinstance(rec.get("cwd"), str):
                cwd = rec["cwd"]
            role = msg.get("role")
            rtype = rec.get("type")

            # token accounting for the usage baseline event
            if rtype == "assistant" or role == "assistant":
                m = msg.get("model")
                if m and m != "<synthetic>":
                    model = m
                usage = msg.get("usage") or {}
                tokens_in += (usage.get("input_tokens") or 0)
                tokens_out += (usage.get("output_tokens") or 0)

            session_seen = True

            # --- UserPromptSubmit rules (secret + PII confirm) ---
            if (rtype == "user" or role == "user"):
                prompt = _prompt_text(msg)
                if prompt:
                    stats["prompts_scanned"] += 1
                    flags = matchers.scan_text(prompt)
                    for dec in (
                        enforce.decide_prompt(flags, pol),
                        enforce.decide_pii_confirm(prompt, flags, pol, raw_session_id),
                    ):
                        if dec is not None:
                            bump(stats["would_block"], dec.rule_id)
                            ev = events.new_event(
                                raw_session_id=raw_session_id, model=None,
                                cwd=cwd, flags=flags, ts=ts,
                                enforcement=enforce.audit_record(pol, dec))
                            out.append(_finalize(ev, _det_id(raw_session_id, idx, dec.rule_id)))

            # --- PreToolUse rules (MCP + restricted-repo) ---
            if (rtype == "assistant" or role == "assistant"):
                content = msg.get("content")
                if isinstance(content, list):
                    for bi, block in enumerate(content):
                        if not isinstance(block, dict) or block.get("type") != "tool_use":
                            continue
                        name = block.get("name")
                        if not isinstance(name, str) or not name:
                            continue
                        stats["tool_calls_scanned"] += 1
                        payload = {"tool_name": name,
                                   "tool_input": block.get("input") or {},
                                   "session_id": raw_session_id, "cwd": cwd}
                        if name.startswith("mcp__"):
                            stats["mcp_calls"] += 1
                            srv, _ = enforce.split_mcp_tool(name)
                            bump(stats["mcp_servers_seen"], srv or "(unknown)")
                            # discovery-mode sensitivity: empty approved list
                            if enforce.decide_pretool(
                                    payload, {**pol, "approved_mcp_servers": []}):
                                stats["mcp_discovery_would_block"] += 1
                        for dec in (
                            enforce.decide_pretool(payload, pol),
                            enforce.decide_restricted_repo(payload, pol),
                        ):
                            if dec is not None:
                                bump(stats["would_block"], dec.rule_id)
                                flags = matchers.scan_obj(block.get("input"))
                                ev = events.new_event(
                                    raw_session_id=raw_session_id, model=None,
                                    cwd=cwd, flags=flags, ts=ts,
                                    enforcement=enforce.audit_record(pol, dec))
                                out.append(_finalize(ev, _det_id(raw_session_id, idx, bi, dec.rule_id)))

        if session_seen:
            stats["transcripts_scanned"] += 1
            stats["sessions"] += 1
            day = (last_activity or "")[:10] or "unknown"
            bump(stats["sessions_by_day"], day)
            # one usage baseline event per session (real tokens, real day)
            ev = events.new_event(
                raw_session_id=raw_session_id, model=model,
                cwd=cwd, tokens_in=tokens_in or None, tokens_out=tokens_out or None,
                flags=[], ts=last_activity)
            out.append(_finalize(ev, _det_id(raw_session_id, "usage")))

    result = {"stats": stats, "events_built": len(out)}
    if dry_run:
        result["dry_run"] = True
        return result

    spool.append(out)
    result["flush"] = spool.flush()
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since-days", type=int, default=14)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    res = run(args.since_days, args.dry_run)
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
