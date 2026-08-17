"""Emit metadata-only usage events for Grok Build runs.

Sources of truth:

1. Explicit CLI flags (--run-id, --model, --tokens-in/--tokens-out, ...)
2. Agent-runner heartbeat env: PAPERCLIP_RUN_ID, PAPERCLIP_AGENT_ID,
   PAPERCLIP_WORKSPACE_CWD, GROK_AGENT, adapter model from agent config if
   provided via --model or AIM_GROK_MODEL
3. **Continuous token path (primary):** ``scan_usage_log`` tails
   ``~/.grok/logs/unified.jsonl`` ``shell.turn.inference_done`` lines and
   emits per-session token *deltas*. This covers all local Grok usage, not
   only agent-runner heartbeats.
4. Optional per-run token resolve: only when
   ``AIM_GROK_RUN_TOKEN_RESOLVE=1`` or explicit ``AIM_GROK_TOKENS_IN/OUT`` /
   CLI tokens are set. Disabled by default so continuous tail + run resolve
   do not double-count the same turns. When enabled, re-emits use deltas
   against the prior cumulative total stored in the checkpoint.
5. Continuous discovery (scan_once / aim watch): agent-runner scratch dirs
   under /tmp/paperclip-run-* plus /proc environ for live adapter mapping,
   then the continuous log tail.

Never reads prompt/response content.
"""
from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any

from . import events, pricing, state, usage

# Agent-runner adapter_type → (schema tool, default provider, default model)
# Only grok_local is emitted by this collector. claude_local / kimi_local are
# tracked in the adapter map so aim watch / coverage can name them; their
# native collectors (claude-code / kimi-code) own the event path.
_ADAPTER_DEFAULTS = {
    "grok_local": ("grok_build", "xai", "grok-4.5"),
    "claude_local": ("claude_code", "anthropic", "claude"),
    "kimi_local": ("kimi_code", "kimi", "kimi"),
}

# Scratch metadata files The agent runner writes per run (metadata only — no prompts).
_SCRATCH_MARKER = ".paperclip-run-scratch.json"
_SCRATCH_GLOB = "paperclip-run-*"
# How far back scan_once looks for unfinished/recent runs (seconds).
_RUN_LOOKBACK_S = 6 * 3600


def _env(name: str) -> str | None:
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else None


def _adapter_map_path() -> Path:
    return state.state_dir() / "paperclip-adapters.json"


def load_adapter_map() -> dict[str, str]:
    """agent_id → adapter_type, learned from live runs (metadata only)."""
    p = _adapter_map_path()
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, str) and v in _ADAPTER_DEFAULTS:
            out[k] = v
    return out


def save_adapter_map(m: dict[str, str]) -> None:
    p = _adapter_map_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, p)


def remember_adapter(agent_id: str | None, adapter_type: str | None) -> None:
    if not agent_id or not adapter_type or adapter_type not in _ADAPTER_DEFAULTS:
        return
    m = load_adapter_map()
    if m.get(agent_id) == adapter_type:
        return
    m[agent_id] = adapter_type
    save_adapter_map(m)


def _decode_jwt_adapter(token: str | None) -> str | None:
    """Best-effort read of adapter_type from an agent-runner JWT payload.

    Does not verify the signature — we only need the claim for tool
    attribution of a process we already observe on this host. Never logs
    the token.
    """
    if not token or token.count(".") < 2:
        return None
    try:
        payload = token.split(".")[1]
        pad = "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload + pad))
    except (ValueError, json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    adapter = data.get("adapter_type")
    return adapter if isinstance(adapter, str) and adapter in _ADAPTER_DEFAULTS else None


def paperclip_context() -> dict[str, Any]:
    """Collect Grok agent-runner metadata available on this process."""
    adapter = None
    if _env("GROK_AGENT"):
        adapter = "grok_local"
    adapter = adapter or _decode_jwt_adapter(_env("PAPERCLIP_API_KEY"))
    return {
        "run_id": _env("PAPERCLIP_RUN_ID"),
        "agent_id": _env("PAPERCLIP_AGENT_ID"),
        "task_id": _env("PAPERCLIP_TASK_ID"),
        "company_id": _env("PAPERCLIP_COMPANY_ID"),
        "workspace_cwd": _env("PAPERCLIP_WORKSPACE_CWD") or _env("PAPERCLIP_WORKSPACE_SOURCE"),
        "wake_reason": _env("PAPERCLIP_WAKE_REASON"),
        "grok_agent": _env("GROK_AGENT"),
        "model": _env("AIM_GROK_MODEL") or _env("GROK_MODEL") or "grok-4.5",
        "adapter_type": adapter or ("grok_local" if _env("GROK_AGENT") or _env("PAPERCLIP_RUN_ID") else None),
    }


def _parse_proc_environ(raw: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in raw.split(b"\0"):
        if not part or b"=" not in part:
            continue
        k, _, v = part.partition(b"=")
        try:
            out[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
        except Exception:
            continue
    return out


def discover_live_adapters() -> dict[str, dict[str, str]]:
    """Scan /proc for agent-runner processes; return run_id → metadata.

    Metadata only: run id, agent id, adapter type. Never reads argv content
    beyond env keys we own, never opens workspace files for content.
    """
    found: dict[str, dict[str, str]] = {}
    proc = Path("/proc")
    if not proc.is_dir():
        return found
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "environ").read_bytes()
        except OSError:
            continue
        env = _parse_proc_environ(raw)
        run_id = (env.get("PAPERCLIP_RUN_ID") or "").strip()
        if not run_id:
            continue
        agent_id = (env.get("PAPERCLIP_AGENT_ID") or "").strip()
        adapter = None
        if (env.get("GROK_AGENT") or "").strip():
            adapter = "grok_local"
        adapter = adapter or _decode_jwt_adapter(env.get("PAPERCLIP_API_KEY"))
        if adapter and agent_id:
            remember_adapter(agent_id, adapter)
        if not adapter and agent_id:
            adapter = load_adapter_map().get(agent_id)
        if adapter != "grok_local":
            # This collector only emits grok_build. Other adapters are
            # remembered for coverage inventory but not spooled here.
            continue
        found[run_id] = {
            "run_id": run_id,
            "agent_id": agent_id,
            "adapter_type": "grok_local",
            "workspace": (env.get("PAPERCLIP_WORKSPACE_CWD") or env.get("PAPERCLIP_WORKSPACE_SOURCE") or "").strip(),
            "model": (env.get("AIM_GROK_MODEL") or env.get("GROK_MODEL") or "grok-4.5").strip(),
        }
    return found


def discover_scratch_runs(*, lookback_s: int = _RUN_LOOKBACK_S) -> list[dict[str, Any]]:
    """List recent agent-runner scratch markers under TMPDIR /tmp.

    The agent runner writes ``.paperclip-run-scratch.json`` per heartbeat with
    runId/agentId/issueId only — no prompt content. We join agentId against
    the learned adapter map so aim watch (which has no PAPERCLIP_RUN_ID of
    its own) can still emit for grok_local agents.
    """
    adapter_map = load_adapter_map()
    now = time.time()
    roots: list[Path] = []
    for key in ("TMPDIR", "TMP", "TEMP"):
        v = os.environ.get(key)
        if v:
            roots.append(Path(v))
    roots.append(Path("/tmp"))
    seen_roots: set[Path] = set()
    out: list[dict[str, Any]] = []
    seen_runs: set[str] = set()
    for root in roots:
        try:
            root = root.resolve()
        except OSError:
            continue
        if root in seen_roots or not root.is_dir():
            continue
        seen_roots.add(root)
        try:
            candidates = list(root.glob(_SCRATCH_GLOB))
        except OSError:
            continue
        for d in candidates:
            marker = d / _SCRATCH_MARKER
            if not marker.is_file():
                continue
            try:
                st = marker.stat()
                if lookback_s and (now - st.st_mtime) > lookback_s:
                    continue
                meta = json.loads(marker.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(meta, dict):
                continue
            run_id = meta.get("runId") or meta.get("run_id")
            agent_id = meta.get("agentId") or meta.get("agent_id")
            if not isinstance(run_id, str) or not run_id or run_id in seen_runs:
                continue
            adapter = adapter_map.get(agent_id) if isinstance(agent_id, str) else None
            if adapter != "grok_local":
                continue
            seen_runs.add(run_id)
            out.append({
                "run_id": run_id,
                "agent_id": agent_id if isinstance(agent_id, str) else None,
                "adapter_type": "grok_local",
                "workspace": None,
                "model": "grok-4.5",
                "ts_epoch_s": st.st_mtime,
            })
    return out


def _truthy_env(name: str) -> bool:
    v = (_env(name) or "").lower()
    return v in ("1", "true", "yes", "on")


def _run_token_resolve_enabled(
    *,
    tokens_in: int | None,
    tokens_out: int | None,
) -> bool:
    """Whether emit_run should attach tokens from the local usage log.

    Continuous ``scan_usage_log`` is the default token path. Per-run
    resolve is opt-in to avoid double-counting the same inference turns.
    Explicit CLI/env token overrides always win and do not need the flag.
    """
    if tokens_in is not None or tokens_out is not None:
        return True
    if _env("AIM_GROK_TOKENS_IN") or _env("GROK_TOKENS_IN"):
        return True
    if _env("AIM_GROK_TOKENS_OUT") or _env("GROK_TOKENS_OUT"):
        return True
    return _truthy_env("AIM_GROK_RUN_TOKEN_RESOLVE")


def _resolve_run_tokens(
    *,
    run_id: str,
    workspace: str | None,
    tokens_in: int | None,
    tokens_out: int | None,
    ts_epoch_s: int | float | None,
) -> tuple[int | None, int | None]:
    """CLI/explicit tokens win; otherwise resolve from local Grok usage log."""
    if tokens_in is not None or tokens_out is not None:
        return tokens_in, tokens_out
    try:
        totals = usage.resolve_tokens_for_run(
            run_id=run_id,
            workspace_path=workspace,
            ts_epoch_s=float(ts_epoch_s) if ts_epoch_s is not None else None,
        )
    except Exception:
        return None, None
    return totals.as_optional()


def _token_delta_against_prior(
    *,
    prior_meta: dict | None,
    resolved_in: int | None,
    resolved_out: int | None,
) -> tuple[int | None, int | None, int | None, int | None, bool]:
    """Convert cumulative resolved totals into an emit delta vs prior meta.

    Returns (emit_in, emit_out, cumulative_in, cumulative_out, should_emit).

    Dashboard SUMs events, so re-emits must carry only the increase since the
    last emission for this run_id — never the full session total again.
    """
    if resolved_in is None and resolved_out is None:
        return None, None, None, None, True  # presence-only is fine

    cum_in = int(resolved_in or 0)
    cum_out = int(resolved_out or 0)
    prior_in = 0
    prior_out = 0
    prior_had = False
    if isinstance(prior_meta, dict):
        if prior_meta.get("tokens_in") is not None:
            prior_had = True
            try:
                prior_in = int(prior_meta.get("tokens_in") or 0)
            except (TypeError, ValueError):
                prior_in = 0
        if prior_meta.get("tokens_out") is not None:
            prior_had = True
            try:
                prior_out = int(prior_meta.get("tokens_out") or 0)
            except (TypeError, ValueError):
                prior_out = 0

    if not prior_had:
        emit_in = cum_in if resolved_in is not None else None
        emit_out = cum_out if resolved_out is not None else None
        return emit_in, emit_out, cum_in, cum_out, True

    din = cum_in - prior_in
    dout = cum_out - prior_out
    if din <= 0 and dout <= 0:
        return None, None, prior_in, prior_out, False
    return (
        din if din > 0 else None,
        dout if dout > 0 else None,
        max(cum_in, prior_in),
        max(cum_out, prior_out),
        True,
    )


def emit_run(
    *,
    run_id: str | None = None,
    model: str | None = None,
    workspace_path: str | None = None,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    adapter_type: str | None = None,
    dry_run: bool = False,
    force: bool = False,
    ts_epoch_s: int | float | None = None,
) -> list[dict]:
    """Emit one usage event for a Grok Build run.

    Dedupes by run_id inside the local checkpoint so re-invoking emit-run
    for the same heartbeat does not flood ingest (unless force=True).

    Token attachment is opt-in: continuous ``scan_usage_log`` is the
    default token path. When per-run resolve is enabled and a prior emission
    already had tokens, only the *delta* vs the prior cumulative total is
    emitted so dashboard SUM cannot double-count.
    """
    ctx = paperclip_context()
    rid = run_id or ctx["run_id"]
    if not rid:
        raise ValueError(
            "no run id: set PAPERCLIP_RUN_ID or pass --run-id "
            "(this collector is meant to run inside a Grok agent-runner heartbeat "
            "or with an explicit run id for dogfood)"
        )
    model_name = model or ctx["model"] or "grok-4.5"
    workspace = workspace_path or ctx["workspace_cwd"]
    adapter = adapter_type or ctx["adapter_type"] or "grok_local"
    if adapter != "grok_local":
        # Refuse to emit non-grok tools from this collector package.
        return []

    agent_id = ctx.get("agent_id")
    remember_adapter(agent_id if isinstance(agent_id, str) else None, adapter)

    want_tokens = _run_token_resolve_enabled(
        tokens_in=tokens_in, tokens_out=tokens_out
    )
    if want_tokens:
        resolved_in, resolved_out = _resolve_run_tokens(
            run_id=rid,
            workspace=workspace if isinstance(workspace, str) else None,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            ts_epoch_s=ts_epoch_s,
        )
    else:
        resolved_in, resolved_out = None, None

    cp = state.load_checkpoint()
    emitted = set(cp.get("emitted_runs") or [])
    meta = cp.get("emitted_run_meta")
    if not isinstance(meta, dict):
        meta = {}
    prior_meta = meta.get(rid) if isinstance(meta.get(rid), dict) else None

    emit_in, emit_out, cum_in, cum_out, should_emit_tokens = _token_delta_against_prior(
        prior_meta=prior_meta,
        resolved_in=resolved_in,
        resolved_out=resolved_out,
    )

    if rid in emitted and not force and not dry_run:
        # Already emitted presence for this run. Only re-emit when we have a
        # positive token delta (first tokens after presence-only, or growth).
        if not should_emit_tokens or (emit_in is None and emit_out is None):
            return []
        # Presence-only prior + still no tokens → nothing new
        if resolved_in is None and resolved_out is None:
            return []

    session_id = events.daily_session_id(rid, epoch_s=ts_epoch_s)
    flags: list[str] = []

    # Opt-in run resolve rarely has cache split; bill uncached-at-input rate.
    cost = pricing.estimate_cost(model_name, emit_in, emit_out)

    ev = events.new_event(
        session_id=session_id,
        model=model_name,
        workspace_path=workspace,
        tokens_in=emit_in,
        tokens_out=emit_out,
        cost_estimate_usd=cost,
        adapter_type=adapter,
        flags=flags,
        status="ok",
        ts_epoch_s=ts_epoch_s,
    )

    if dry_run:
        return [ev]

    from . import spool
    spool.append([ev])
    emitted.add(rid)
    # Cap checkpoint growth
    if len(emitted) > 5000:
        emitted = set(list(emitted)[-2500:])
    cp["emitted_runs"] = sorted(emitted)
    # Store *cumulative* resolved totals so the next delta is correct.
    store_in = cum_in if cum_in is not None else emit_in
    store_out = cum_out if cum_out is not None else emit_out
    # If this was presence-only, keep prior token cumulatives when present.
    if store_in is None and isinstance(prior_meta, dict):
        store_in = prior_meta.get("tokens_in")
    if store_out is None and isinstance(prior_meta, dict):
        store_out = prior_meta.get("tokens_out")
    meta[rid] = {
        "tokens_in": store_in,
        "tokens_out": store_out,
        "ts": events.format_ts(ts_epoch_s),
    }
    if len(meta) > 5000:
        keep = set(cp["emitted_runs"])
        meta = {k: v for k, v in meta.items() if k in keep}
    cp["emitted_run_meta"] = meta
    state.save_checkpoint(cp)
    # Best-effort flush so dogfood shows up in the same heartbeat cycle.
    try:
        spool.flush()
    except Exception:
        pass
    return [ev]


def scan_usage_log(*, dry_run: bool = False) -> list[dict]:
    """Emit per-session token deltas from the local Grok usage log.

    Primary token path for ``aim watch`` / ``scan-once``. Metadata only —
    numeric counters from ``shell.turn.inference_done``. Does not require a
    Agent-runner id. First sight of the log starts at EOF unless
    ``AIM_GROK_LOG_BACKFILL_BYTES`` is set.
    """
    cp = state.load_checkpoint()
    try:
        deltas = usage.scan_inference_log(cp)
    except Exception:
        return []
    if not deltas:
        if not dry_run:
            state.save_checkpoint(cp)
        return []

    model_name = _env("AIM_GROK_MODEL") or _env("GROK_MODEL") or "grok-4.5"
    out: list[dict] = []
    for d in deltas:
        if d.tokens_in <= 0 and d.tokens_out <= 0:
            continue
        sid = events.daily_session_id(d.session_id, epoch_s=d.last_ts_epoch)
        tin = d.tokens_in if d.tokens_in > 0 else None
        tout = d.tokens_out if d.tokens_out > 0 else None
        # cache-aware list-price estimate (collector cost wins in COST_SQL).
        cost = pricing.estimate_cost(
            model_name,
            d.tokens_in,
            d.tokens_out,
            tokens_cached=d.tokens_cached,
        )
        ev = events.new_event(
            session_id=sid,
            model=model_name,
            workspace_path=None,
            tokens_in=tin,
            tokens_out=tout,
            cost_estimate_usd=cost,
            adapter_type="grok_local",
            flags=[],
            status="ok",
            ts_epoch_s=d.last_ts_epoch,
        )
        out.append(ev)

    if dry_run:
        return out

    if out:
        from . import spool
        spool.append(out)
        try:
            spool.flush()
        except Exception:
            pass
    state.save_checkpoint(cp)
    return out


def scan_once(*, dry_run: bool = False) -> list[dict]:
    """Continuous emission entrypoint for `aim watch` / `scan-once`.

    1. If *this* process is inside a Grok agent-runner, emit presence.
    2. Discover other live grok_local agent-runner processes via /proc.
    3. Discover recent agent-runner scratch dirs for known grok agents.
    4. Tail ``~/.grok/logs/unified.jsonl`` for per-session token deltas
       (— primary token accounting path).

    Deduped by run_id for agent-runner presence. Never requires a human to call
    ``emit-run``.
    """
    emitted: list[dict] = []
    seen: set[str] = set()

    def _take(run_id: str, **kwargs: Any) -> None:
        if run_id in seen:
            return
        seen.add(run_id)
        try:
            evs = emit_run(run_id=run_id, dry_run=dry_run, **kwargs)
        except ValueError:
            return
        emitted.extend(evs)

    ctx = paperclip_context()
    if ctx["run_id"] and (ctx["adapter_type"] == "grok_local" or ctx["grok_agent"]):
        remember_adapter(ctx.get("agent_id"), "grok_local")
        _take(
            ctx["run_id"],
            model=ctx.get("model"),
            workspace_path=ctx.get("workspace_cwd"),
            adapter_type="grok_local",
        )

    for meta in discover_live_adapters().values():
        _take(
            meta["run_id"],
            model=meta.get("model") or "grok-4.5",
            workspace_path=meta.get("workspace") or None,
            adapter_type="grok_local",
        )

    for meta in discover_scratch_runs():
        _take(
            meta["run_id"],
            model=meta.get("model") or "grok-4.5",
            workspace_path=meta.get("workspace"),
            adapter_type="grok_local",
            ts_epoch_s=meta.get("ts_epoch_s"),
        )

    # Primary token path: all local Grok inference turns.
    emitted.extend(scan_usage_log(dry_run=dry_run))
    return emitted
