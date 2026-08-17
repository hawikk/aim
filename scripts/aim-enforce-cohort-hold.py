#!/usr/bin/env python3
"""AIM-684: cohort enforce rollout ops tooling + automatic hold on FP spike.

Rolls endpoint enforce to a % host cohort (AIM-793 ladder bundles) and freezes
actuation (percent=0) when the detector session FP rate spikes above SLO with
enough volume (AIM-672 semantics).

This is **ops tooling** — pure local decision + bundle install. It does not
call production APIs unless ``--api-url`` is set for live FP metrics. Privacy-ok:
never logs host ids, salts, or prompt content.

Status machine (state file ``cohort-rollout.json``):

  idle → running → completed
               ↘ held   (FP spike auto-hold or operator hold)
               ↘ aborted (operator aborted to shadow)

Usage:
  # Ladder + defaults
  python3 scripts/aim-enforce-cohort-hold.py --ladder

  # Start canary at 5% (installs deploy/enforcement/enforcement.cohort-5.json)
  python3 scripts/aim-enforce-cohort-hold.py --start --percent 5

  # Tick: expand on green / auto-hold on FP spike
  python3 scripts/aim-enforce-cohort-hold.py --tick \\
      --sessions 1000 --fp-sessions 0
  python3 scripts/aim-enforce-cohort-hold.py --tick \\
      --sessions 1000 --fp-sessions 12     # 1.2% > 0.5% → hold

  # Live FP rate (optional):
  python3 scripts/aim-enforce-cohort-hold.py --tick --api-url http://127.0.0.1:8080 \\
      --cookie-jar /tmp/admin.cookie

  # Force hold / expand / status
  python3 scripts/aim-enforce-cohort-hold.py --hold --reason operator_kill_switch
  python3 scripts/aim-enforce-cohort-hold.py --expand
  python3 scripts/aim-enforce-cohort-hold.py --status

  # Offline dogfood (no install):
  python3 scripts/aim-enforce-cohort-hold.py --self-test
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Defaults (aligned with AIM-793 ladder + AIM-672 session FP SLO)
# ---------------------------------------------------------------------------

SCHEMA = "aim.enforce-cohort-rollout/v1"
DEFAULT_LADDER = (0, 5, 25, 100)
DEFAULT_FP_SLO_PCT = 0.5  # session_fp_rate < 0.5%
DEFAULT_MIN_SESSIONS = 20
STATE_FILENAME = "cohort-rollout.json"
HOLD_PERCENT = 0  # auto-hold installs cohort-0 (config present, nobody actuated)

# Bundles under deploy/enforcement/
BUNDLE_BY_PERCENT = {
    0: "enforcement.cohort-0.json",
    5: "enforcement.cohort-5.json",
    25: "enforcement.cohort-25.json",
    100: "enforcement.cohort-100.json",
}


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_bundle_dir() -> Path:
    return repo_root() / "deploy" / "enforcement"


def default_state_dir() -> Path:
    env = os.environ.get("AIM_STATE_DIR")
    if env:
        return Path(env)
    return Path.home() / ".aim-collector"


def normalize_ladder(raw: Any) -> list[int]:
    if raw is None:
        steps = list(DEFAULT_LADDER)
    elif isinstance(raw, str):
        steps = [int(x.strip()) for x in raw.split(",") if x.strip()]
    else:
        steps = [int(x) for x in raw]
    if not steps:
        raise ValueError("ladder must not be empty")
    out: list[int] = []
    prev = -1
    for p in steps:
        if p < 0 or p > 100:
            raise ValueError(f"invalid ladder step {p} (need 0..100)")
        if p <= prev:
            raise ValueError(f"ladder must be strictly increasing; got {p} after {prev}")
        out.append(p)
        prev = p
    return out


def evaluate_session_fp_rate(
    sessions: int,
    fp_sessions: int,
    *,
    max_session_fp_pct: float = DEFAULT_FP_SLO_PCT,
) -> dict[str, Any]:
    """Pure AIM-672-shaped evaluator (no DB)."""
    sessions = max(0, int(sessions))
    fp_sessions = max(0, min(int(fp_sessions), sessions))
    rate = (fp_sessions / sessions) if sessions else 0.0
    rate_pct = round(rate * 10000) / 100  # two decimal places of a percent
    max_rate = max_session_fp_pct / 100.0
    breached = sessions > 0 and rate > max_rate
    if sessions == 0:
        state = "never_configured"
    elif breached:
        state = "broken"
    else:
        state = "ok"
    return {
        "sessions": sessions,
        "fpSessions": fp_sessions,
        "sessionFpRate": rate,
        "sessionFpRatePct": rate_pct,
        "sloPct": max_session_fp_pct,
        "breached": breached,
        "state": state,
    }


def evaluate_tick(
    state: dict[str, Any] | None,
    fp: dict[str, Any] | None,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    """Pure decision: idle | hold | expand | complete | auto_hold.

    Auto-hold (FP spike) requires ALL of:
      - status == running
      - sessions >= minSessions
      - FP evaluation state == broken
    Insufficient volume always holds (never expand, never auto-hold).
    """
    at = now or utcnow()
    if not state or state.get("status") in (None, "idle"):
        return {
            "action": "idle",
            "reason": "no_active_canary",
            "shouldInstallHold": False,
            "shouldExpand": False,
            "nextState": state,
            "fp": fp,
            "at": at,
        }

    status = state.get("status")
    if status in ("held", "completed", "aborted"):
        return {
            "action": "hold",
            "reason": f"canary_{status}",
            "shouldInstallHold": False,
            "shouldExpand": False,
            "nextState": state,
            "fp": fp,
            "at": at,
        }

    # status == running
    min_sessions = int(state.get("minSessions") or DEFAULT_MIN_SESSIONS)
    fp_slo = float(state.get("fpSloPct") if state.get("fpSloPct") is not None else DEFAULT_FP_SLO_PCT)
    sessions = int((fp or {}).get("sessions") or 0)

    if fp is None:
        return {
            "action": "hold",
            "reason": "fp_metrics_unavailable",
            "shouldInstallHold": False,
            "shouldExpand": False,
            "nextState": state,
            "fp": None,
            "at": at,
        }

    if sessions < min_sessions:
        return {
            "action": "hold",
            "reason": "insufficient_sessions",
            "shouldInstallHold": False,
            "shouldExpand": False,
            "nextState": {
                **state,
                "updatedAt": at,
                "lastDecision": {
                    "action": "hold",
                    "reason": "insufficient_sessions",
                    "at": at,
                    "cohortPercent": state.get("cohortPercent"),
                    "fp": fp,
                },
            },
            "fp": fp,
            "at": at,
        }

    if fp.get("state") == "broken" or fp.get("breached"):
        # Automatic hold on FP spike → percent 0
        history = list(state.get("history") or [])
        history.append(
            {
                "action": "auto_hold",
                "reason": "fp_spike",
                "at": at,
                "cohortPercent": HOLD_PERCENT,
                "previousPercent": state.get("cohortPercent"),
                "fp": fp,
            }
        )
        next_state = {
            **state,
            "status": "held",
            "cohortPercent": HOLD_PERCENT,
            "stepIndex": 0 if 0 in (state.get("ladder") or []) else state.get("stepIndex"),
            "heldAt": at,
            "updatedAt": at,
            "lastDecision": {
                "action": "auto_hold",
                "reason": "fp_spike",
                "at": at,
                "cohortPercent": HOLD_PERCENT,
                "fp": fp,
            },
            "history": history,
        }
        return {
            "action": "auto_hold",
            "reason": "fp_spike",
            "shouldInstallHold": True,
            "shouldExpand": False,
            "nextState": next_state,
            "fp": fp,
            "at": at,
            "alert": {
                "finding_type": "ai_usage.enforce_cohort_fp_hold",
                "severity": "high",
                "summary": (
                    f"Enforce canary held at 0% after FP spike: "
                    f"{fp.get('sessionFpRatePct')}% > SLO {fp_slo}% "
                    f"(sessions={sessions})"
                ),
                "fp": fp,
                "previousPercent": state.get("cohortPercent"),
            },
        }

    # Under SLO with enough volume → expand or complete
    ladder = list(state.get("ladder") or DEFAULT_LADDER)
    step = int(state.get("stepIndex") or 0)
    if step >= len(ladder) - 1:
        history = list(state.get("history") or [])
        history.append(
            {
                "action": "complete",
                "reason": "ladder_complete_under_slo",
                "at": at,
                "cohortPercent": ladder[-1],
                "fp": fp,
            }
        )
        next_state = {
            **state,
            "status": "completed",
            "cohortPercent": ladder[-1],
            "completedAt": at,
            "updatedAt": at,
            "lastDecision": {
                "action": "complete",
                "reason": "ladder_complete_under_slo",
                "at": at,
                "cohortPercent": ladder[-1],
                "fp": fp,
            },
            "history": history,
        }
        return {
            "action": "complete",
            "reason": "ladder_complete_under_slo",
            "shouldInstallHold": False,
            "shouldExpand": False,
            "nextState": next_state,
            "fp": fp,
            "at": at,
        }

    next_step = step + 1
    next_pct = ladder[next_step]
    history = list(state.get("history") or [])
    history.append(
        {
            "action": "expand",
            "reason": "under_slo",
            "at": at,
            "cohortPercent": next_pct,
            "previousPercent": state.get("cohortPercent"),
            "fp": fp,
        }
    )
    next_state = {
        **state,
        "status": "running",
        "stepIndex": next_step,
        "cohortPercent": next_pct,
        "updatedAt": at,
        "lastDecision": {
            "action": "expand",
            "reason": "under_slo",
            "at": at,
            "cohortPercent": next_pct,
            "fp": fp,
        },
        "history": history,
    }
    return {
        "action": "expand",
        "reason": "under_slo",
        "shouldInstallHold": False,
        "shouldExpand": True,
        "nextState": next_state,
        "fp": fp,
        "at": at,
    }


def create_rollout_state(
    *,
    percent: int,
    ladder: list[int] | None = None,
    fp_slo_pct: float = DEFAULT_FP_SLO_PCT,
    min_sessions: int = DEFAULT_MIN_SESSIONS,
    actor: str = "ops",
    note: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    lad = normalize_ladder(ladder if ladder is not None else DEFAULT_LADDER)
    if percent not in lad:
        # Allow start at a rung not in ladder only if we inject it sorted.
        lad = normalize_ladder(sorted(set(lad + [percent])))
    step = lad.index(percent)
    at = now or utcnow()
    return {
        "schema": SCHEMA,
        "status": "running",
        "ladder": lad,
        "stepIndex": step,
        "cohortPercent": percent,
        "fpSloPct": float(fp_slo_pct),
        "minSessions": int(min_sessions),
        "startedAt": at,
        "startedBy": actor,
        "updatedAt": at,
        "heldAt": None,
        "completedAt": None,
        "abortedAt": None,
        "lastDecision": {
            "action": "start",
            "reason": note or "canary_started",
            "at": at,
            "cohortPercent": percent,
            "fp": None,
        },
        "history": [
            {
                "action": "start",
                "reason": note or "canary_started",
                "at": at,
                "actor": actor,
                "cohortPercent": percent,
                "stepIndex": step,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Bundle install / state I/O
# ---------------------------------------------------------------------------


def bundle_path_for_percent(percent: int, bundle_dir: Path) -> Path:
    name = BUNDLE_BY_PERCENT.get(int(percent))
    if name:
        p = bundle_dir / name
        if p.is_file():
            return p
    # Fall back: synthesize from cohort-5 or enforce base by rewriting percent.
    for candidate in (
        bundle_dir / "enforcement.cohort-5.json",
        bundle_dir / "enforcement.enforce.json",
    ):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"no cohort bundle for percent={percent} under {bundle_dir}"
    )


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def materialize_bundle(
    percent: int,
    *,
    bundle_dir: Path,
    dest: Path,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Install a cohort bundle at ``dest``, rewriting percent if needed."""
    src = bundle_path_for_percent(percent, bundle_dir)
    data = load_json(src)
    # Ensure secret rule cohort percent matches target (prebuilt files already do).
    rules = data.setdefault("rules", {})
    secret = rules.setdefault("secret-pattern-in-prompt", {})
    secret["enforce"] = True
    cohort = secret.get("cohort")
    if not isinstance(cohort, dict):
        cohort = {"percent": percent, "salt": "secret-pattern-canary-2026-08"}
        secret["cohort"] = cohort
    else:
        cohort["percent"] = int(percent)
        if percent >= 100:
            # 100% may omit cohort (fleet-wide); keep explicit for auditability.
            cohort["percent"] = 100
    if percent == 0:
        cohort["percent"] = 0
    # Distinct policy_hash bump when we rewrote percent vs source file.
    src_pct = None
    try:
        src_pct = (
            (load_json(src).get("rules") or {})
            .get("secret-pattern-in-prompt", {})
            .get("cohort", {})
            .get("percent")
        )
    except Exception:
        src_pct = None
    if src_pct != percent:
        base_hash = str(data.get("policy_hash") or "aim684-cohort")
        data["policy_hash"] = f"{base_hash}-p{percent}"

    data["mode"] = "enforce"
    if dry_run:
        return {
            "src": str(src),
            "dest": str(dest),
            "dry_run": True,
            "mode": data.get("mode"),
            "policy_hash": data.get("policy_hash"),
            "cohort_percent": percent,
        }

    dest.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomic(dest, data)
    return {
        "src": str(src),
        "dest": str(dest),
        "dry_run": False,
        "mode": data.get("mode"),
        "policy_hash": data.get("policy_hash"),
        "cohort_percent": percent,
    }


def install_shadow(*, bundle_dir: Path, dest: Path, dry_run: bool = False) -> dict[str, Any]:
    src = bundle_dir / "enforcement.shadow.json"
    if not src.is_file():
        raise FileNotFoundError(src)
    if dry_run:
        return {"src": str(src), "dest": str(dest), "dry_run": True, "mode": "shadow"}
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    data = load_json(dest)
    return {
        "src": str(src),
        "dest": str(dest),
        "dry_run": False,
        "mode": data.get("mode"),
        "policy_hash": data.get("policy_hash"),
    }


def state_path(state_dir: Path) -> Path:
    return state_dir / STATE_FILENAME


def load_state(state_dir: Path) -> dict[str, Any] | None:
    p = state_path(state_dir)
    if not p.is_file():
        return None
    try:
        return load_json(p)
    except (json.JSONDecodeError, OSError):
        return None


def save_state(state_dir: Path, state: dict[str, Any], *, dry_run: bool = False) -> Path:
    p = state_path(state_dir)
    if dry_run:
        return p
    write_json_atomic(p, state)
    return p


def enforcement_dest(state_dir: Path, managed: bool) -> Path:
    if managed:
        return Path("/etc/aim-collector/enforcement.json")
    return state_dir / "enforcement.json"


def fetch_live_fp(
    api_url: str,
    *,
    cookie_jar: Path | None = None,
    token: str | None = None,
    days: int = 7,
) -> dict[str, Any]:
    """GET /api/security/fp-rate and map to evaluate_session_fp_rate inputs."""
    base = api_url.rstrip("/")
    url = f"{base}/api/security/fp-rate?days={int(days)}"
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    # Optional cookie header from a Netscape/curl cookie file (simple Cookie: line)
    if cookie_jar and cookie_jar.is_file():
        raw = cookie_jar.read_text(encoding="utf-8").strip()
        if raw.startswith("Cookie:"):
            headers["Cookie"] = raw.split(":", 1)[1].strip()
            req = urllib.request.Request(url, headers=headers, method="GET")
        elif "=" in raw and "\t" not in raw.split("\n", 1)[0]:
            # single Cookie header body
            headers["Cookie"] = raw
            req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"fp-rate HTTP {e.code}: {e.read()[:200]!r}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"fp-rate unreachable: {e}") from e

    sessions = body.get("sessions")
    if sessions is None:
        sessions = (body.get("counts") or {}).get("sessions")
    fp_sessions = body.get("fpSessions")
    if fp_sessions is None:
        fp_sessions = body.get("fp_sessions")
    if fp_sessions is None:
        fp_sessions = (body.get("counts") or {}).get("fpSessions")
    slo = body.get("sloPct") or body.get("maxSessionFpPct") or DEFAULT_FP_SLO_PCT
    return evaluate_session_fp_rate(
        int(sessions or 0),
        int(fp_sessions or 0),
        max_session_fp_pct=float(slo),
    )


def ladder_text() -> str:
    return """# Enforce cohort rollout ladder + FP hold (AIM-684 / AIM-793)

Expand/rollback is a **policy-hash bump only** — install a cohort bundle, no collector release.

| Step | Global mode | Rule enforce | Cohort percent | Intent |
|------|-------------|--------------|----------------|--------|
| 0    | enforce     | true         | 0              | Config present; nobody actuated (HOLD target) |
| 1    | enforce     | true         | 5              | Dogfood / canary hosts |
| 2    | enforce     | true         | 25             | Broader pilot |
| 3    | enforce     | true         | 100            | Fleet-wide |

## Automatic hold on FP spike

On each ``--tick``:

1. Measure session FP rate (injected metrics or ``GET /api/security/fp-rate``).
2. If ``sessions >= minSessions`` (default 20) **and** rate > SLO (default 0.5%):
   - status → ``held``
   - install **cohort percent 0** (``enforcement.cohort-0.json``)
   - emit ``ai_usage.enforce_cohort_fp_hold`` alert payload on stdout JSON
3. If under SLO with enough volume → expand one ladder step.
4. If insufficient volume → hold current percent (never expand, never auto-hold).

Kill-switch: ``--hold`` (percent 0) or ``--abort`` (shadow bundle).

State file: ``$AIM_STATE_DIR/cohort-rollout.json`` (default ``~/.aim-collector/``).
"""


def self_test() -> int:
    """Offline dogfood of decision logic + bundle materialize (temp dir)."""
    failures = 0

    def check(cond: bool, msg: str) -> None:
        nonlocal failures
        if not cond:
            print(f"FAIL: {msg}")
            failures += 1
        else:
            print(f"PASS: {msg}")

    # FP evaluator
    ok = evaluate_session_fp_rate(1000, 0)
    check(ok["state"] == "ok" and ok["sessionFpRatePct"] == 0.0, "fp ok at 0%")
    broken = evaluate_session_fp_rate(1000, 12)  # 1.2%
    check(broken["state"] == "broken" and broken["breached"], "fp broken at 1.2%")
    empty = evaluate_session_fp_rate(0, 0)
    check(empty["state"] == "never_configured", "fp never_configured at 0 sessions")

    # Tick: insufficient volume holds
    st = create_rollout_state(percent=5, min_sessions=20, now="2026-08-01T00:00:00Z")
    d = evaluate_tick(st, evaluate_session_fp_rate(5, 1), now="2026-08-01T01:00:00Z")
    check(d["action"] == "hold" and d["reason"] == "insufficient_sessions", "hold on low volume")
    check(not d["shouldInstallHold"], "low volume does not install hold")

    # Tick: FP spike → auto_hold
    d = evaluate_tick(st, evaluate_session_fp_rate(1000, 12), now="2026-08-01T02:00:00Z")
    check(d["action"] == "auto_hold", "auto_hold on FP spike")
    check(d["shouldInstallHold"] is True, "auto_hold installs hold bundle")
    check(d["nextState"]["status"] == "held", "status held")
    check(d["nextState"]["cohortPercent"] == 0, "held at percent 0")
    check(d.get("alert", {}).get("finding_type") == "ai_usage.enforce_cohort_fp_hold", "alert payload")

    # Tick: expand under SLO
    st2 = create_rollout_state(
        percent=5, ladder=[5, 25, 100], min_sessions=20, now="2026-08-01T00:00:00Z"
    )
    d = evaluate_tick(st2, evaluate_session_fp_rate(1000, 0), now="2026-08-01T03:00:00Z")
    check(d["action"] == "expand" and d["shouldExpand"], "expand under SLO")
    check(d["nextState"]["cohortPercent"] == 25, "expand 5→25")

    # Tick: complete at final rung
    st3 = create_rollout_state(
        percent=100, ladder=[5, 25, 100], min_sessions=20, now="2026-08-01T00:00:00Z"
    )
    d = evaluate_tick(st3, evaluate_session_fp_rate(1000, 0), now="2026-08-01T04:00:00Z")
    check(d["action"] == "complete", "complete at 100% under SLO")
    check(d["nextState"]["status"] == "completed", "status completed")

    # Terminal state holds
    d = evaluate_tick(d["nextState"], evaluate_session_fp_rate(1000, 50), now="2026-08-01T05:00:00Z")
    check(d["action"] == "hold" and not d["shouldInstallHold"], "completed ignores further FP")

    # Bundle materialize in temp
    with tempfile.TemporaryDirectory(prefix="aim684-") as td:
        tdp = Path(td)
        dest = tdp / "enforcement.json"
        info = materialize_bundle(5, bundle_dir=default_bundle_dir(), dest=dest)
        check(dest.is_file(), "installed cohort-5")
        data = load_json(dest)
        pct = (
            (data.get("rules") or {})
            .get("secret-pattern-in-prompt", {})
            .get("cohort", {})
            .get("percent")
        )
        check(pct == 5, f"cohort percent 5 (got {pct})")
        info0 = materialize_bundle(0, bundle_dir=default_bundle_dir(), dest=dest)
        data0 = load_json(dest)
        pct0 = (
            (data0.get("rules") or {})
            .get("secret-pattern-in-prompt", {})
            .get("cohort", {})
            .get("percent")
        )
        check(pct0 == 0, "hold install percent 0")
        check(info0["cohort_percent"] == 0, "hold install result")
        # State round-trip
        st = create_rollout_state(percent=5)
        save_state(tdp, st)
        loaded = load_state(tdp)
        check(loaded is not None and loaded["cohortPercent"] == 5, "state round-trip")

    print("## self_test_summary")
    print(json.dumps({"failures": failures, "ok": failures == 0}, indent=2))
    return 1 if failures else 0


def emit(obj: Any, *, as_json: bool) -> None:
    if as_json:
        json.dump(obj, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("history", "nextState") and isinstance(v, (dict, list)):
                print(f"{k}: {json.dumps(v)[:200]}…")
            else:
                print(f"{k}: {v}")
    else:
        print(obj)


def resolve_fp_metrics(args: argparse.Namespace, state: dict[str, Any] | None) -> dict[str, Any] | None:
    if args.sessions is not None:
        slo = float(
            args.fp_slo_pct
            if args.fp_slo_pct is not None
            else (state or {}).get("fpSloPct")
            or DEFAULT_FP_SLO_PCT
        )
        return evaluate_session_fp_rate(
            args.sessions,
            args.fp_sessions or 0,
            max_session_fp_pct=slo,
        )
    if args.api_url:
        return fetch_live_fp(
            args.api_url,
            cookie_jar=Path(args.cookie_jar) if args.cookie_jar else None,
            token=args.token or os.environ.get("AIM_API_TOKEN"),
            days=args.days,
        )
    return None


def cmd_start(args: argparse.Namespace) -> int:
    ladder = normalize_ladder(args.ladder_steps if args.ladder_steps else DEFAULT_LADDER)
    percent = int(args.percent if args.percent is not None else ladder[0] if ladder[0] > 0 else (ladder[1] if len(ladder) > 1 else 5))
    state = create_rollout_state(
        percent=percent,
        ladder=ladder,
        fp_slo_pct=float(args.fp_slo_pct if args.fp_slo_pct is not None else DEFAULT_FP_SLO_PCT),
        min_sessions=int(args.min_sessions),
        actor=args.actor,
        note=args.reason or "canary_started",
    )
    dest = enforcement_dest(args.state_dir, args.managed)
    install = materialize_bundle(
        percent,
        bundle_dir=args.bundle_dir,
        dest=dest,
        dry_run=args.dry_run,
    )
    sp = save_state(args.state_dir, state, dry_run=args.dry_run)
    out = {
        "action": "start",
        "state": state,
        "install": install,
        "statePath": str(sp),
        "dryRun": bool(args.dry_run),
    }
    emit(out if args.json else {
        "action": "start",
        "status": state["status"],
        "cohortPercent": percent,
        "policy_hash": install.get("policy_hash"),
        "dest": install.get("dest"),
        "statePath": str(sp),
        "dryRun": bool(args.dry_run),
    }, as_json=args.json)
    return 0


def cmd_tick(args: argparse.Namespace) -> int:
    state = load_state(args.state_dir)
    if not state and not args.dry_run:
        # Allow pure decision dry-run without prior start when metrics injected
        if args.sessions is None and not args.api_url:
            print("error: no rollout state; run --start first", file=sys.stderr)
            return 2
        state = create_rollout_state(
            percent=int(args.percent or 5),
            ladder=normalize_ladder(args.ladder_steps) if args.ladder_steps else list(DEFAULT_LADDER),
            fp_slo_pct=float(args.fp_slo_pct or DEFAULT_FP_SLO_PCT),
            min_sessions=int(args.min_sessions),
            actor=args.actor,
            note="ephemeral_tick",
        )

    try:
        fp = resolve_fp_metrics(args, state)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    decision = evaluate_tick(state, fp)
    dest = enforcement_dest(args.state_dir, args.managed)
    install = None
    next_state = decision.get("nextState") or state

    if decision.get("shouldInstallHold"):
        install = materialize_bundle(
            HOLD_PERCENT,
            bundle_dir=args.bundle_dir,
            dest=dest,
            dry_run=args.dry_run,
        )
    elif decision.get("shouldExpand"):
        pct = int(next_state.get("cohortPercent") or HOLD_PERCENT)
        install = materialize_bundle(
            pct,
            bundle_dir=args.bundle_dir,
            dest=dest,
            dry_run=args.dry_run,
        )

    if next_state and next_state is not state:
        save_state(args.state_dir, next_state, dry_run=args.dry_run)

    out = {
        "action": decision["action"],
        "reason": decision["reason"],
        "status": (next_state or {}).get("status"),
        "cohortPercent": (next_state or {}).get("cohortPercent"),
        "fp": fp,
        "install": install,
        "alert": decision.get("alert"),
        "dryRun": bool(args.dry_run),
    }
    emit(out, as_json=args.json)
    # Exit 1 on auto_hold so cron can page; 0 otherwise.
    return 1 if decision["action"] == "auto_hold" else 0


def cmd_hold(args: argparse.Namespace) -> int:
    state = load_state(args.state_dir) or create_rollout_state(
        percent=int(args.percent or 5),
        actor=args.actor,
        note="hold_without_prior_start",
    )
    at = utcnow()
    history = list(state.get("history") or [])
    history.append(
        {
            "action": "hold",
            "reason": args.reason or "operator_hold",
            "at": at,
            "actor": args.actor,
            "cohortPercent": HOLD_PERCENT,
            "previousPercent": state.get("cohortPercent"),
        }
    )
    state = {
        **state,
        "status": "held",
        "cohortPercent": HOLD_PERCENT,
        "heldAt": at,
        "updatedAt": at,
        "lastDecision": {
            "action": "hold",
            "reason": args.reason or "operator_hold",
            "at": at,
            "cohortPercent": HOLD_PERCENT,
            "fp": None,
        },
        "history": history,
    }
    dest = enforcement_dest(args.state_dir, args.managed)
    install = materialize_bundle(
        HOLD_PERCENT,
        bundle_dir=args.bundle_dir,
        dest=dest,
        dry_run=args.dry_run,
    )
    sp = save_state(args.state_dir, state, dry_run=args.dry_run)
    emit({
        "action": "hold",
        "reason": args.reason or "operator_hold",
        "status": "held",
        "cohortPercent": 0,
        "install": install,
        "statePath": str(sp),
        "dryRun": bool(args.dry_run),
    }, as_json=args.json)
    return 0


def cmd_expand(args: argparse.Namespace) -> int:
    state = load_state(args.state_dir)
    if not state or state.get("status") != "running":
        print("error: expand requires a running canary (use --start)", file=sys.stderr)
        return 2
    # Force expand by faking green FP with enough volume
    min_s = int(state.get("minSessions") or DEFAULT_MIN_SESSIONS)
    fp = evaluate_session_fp_rate(
        max(min_s, args.sessions or min_s),
        args.fp_sessions or 0,
        max_session_fp_pct=float(state.get("fpSloPct") or DEFAULT_FP_SLO_PCT),
    )
    decision = evaluate_tick(state, fp)
    if decision["action"] not in ("expand", "complete"):
        emit({"action": decision["action"], "reason": decision["reason"], "fp": fp}, as_json=args.json)
        return 1
    next_state = decision["nextState"]
    dest = enforcement_dest(args.state_dir, args.managed)
    install = None
    if decision.get("shouldExpand"):
        install = materialize_bundle(
            int(next_state["cohortPercent"]),
            bundle_dir=args.bundle_dir,
            dest=dest,
            dry_run=args.dry_run,
        )
    save_state(args.state_dir, next_state, dry_run=args.dry_run)
    emit({
        "action": decision["action"],
        "reason": decision["reason"],
        "status": next_state.get("status"),
        "cohortPercent": next_state.get("cohortPercent"),
        "install": install,
        "dryRun": bool(args.dry_run),
    }, as_json=args.json)
    return 0


def cmd_abort(args: argparse.Namespace) -> int:
    state = load_state(args.state_dir) or {
        "schema": SCHEMA,
        "status": "idle",
        "history": [],
    }
    at = utcnow()
    history = list(state.get("history") or [])
    history.append(
        {
            "action": "abort",
            "reason": args.reason or "operator_abort_shadow",
            "at": at,
            "actor": args.actor,
        }
    )
    state = {
        **state,
        "status": "aborted",
        "cohortPercent": 0,
        "abortedAt": at,
        "updatedAt": at,
        "lastDecision": {
            "action": "abort",
            "reason": args.reason or "operator_abort_shadow",
            "at": at,
            "cohortPercent": 0,
            "fp": None,
        },
        "history": history,
    }
    dest = enforcement_dest(args.state_dir, args.managed)
    install = install_shadow(
        bundle_dir=args.bundle_dir, dest=dest, dry_run=args.dry_run
    )
    save_state(args.state_dir, state, dry_run=args.dry_run)
    emit({
        "action": "abort",
        "status": "aborted",
        "install": install,
        "dryRun": bool(args.dry_run),
    }, as_json=args.json)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    state = load_state(args.state_dir)
    dest = enforcement_dest(args.state_dir, args.managed)
    installed = None
    if dest.is_file():
        try:
            data = load_json(dest)
            secret = (data.get("rules") or {}).get("secret-pattern-in-prompt") or {}
            cohort = secret.get("cohort") if isinstance(secret.get("cohort"), dict) else {}
            installed = {
                "path": str(dest),
                "mode": data.get("mode"),
                "policy_hash": data.get("policy_hash"),
                "secret_enforce": secret.get("enforce"),
                "cohort_percent": cohort.get("percent"),
            }
        except (json.JSONDecodeError, OSError) as e:
            installed = {"path": str(dest), "error": str(e)}
    emit({
        "statePath": str(state_path(args.state_dir)),
        "state": state,
        "installed": installed,
    }, as_json=True if args.json else args.json)
    if not args.json:
        if not state:
            print("status: no rollout state")
        else:
            print(f"status: {state.get('status')}")
            print(f"cohortPercent: {state.get('cohortPercent')}")
            print(f"ladder: {state.get('ladder')}")
            print(f"fpSloPct: {state.get('fpSloPct')}")
            print(f"minSessions: {state.get('minSessions')}")
            ld = state.get("lastDecision") or {}
            print(f"lastDecision: {ld.get('action')} ({ld.get('reason')})")
        if installed:
            print(f"installed: mode={installed.get('mode')} hash={installed.get('policy_hash')} "
                  f"cohort%={installed.get('cohort_percent')} path={installed.get('path')}")
        else:
            print(f"installed: (missing) {dest}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ladder", action="store_true", help="print rollout ladder + hold semantics")
    ap.add_argument("--self-test", action="store_true", help="offline dogfood; exit 1 on failure")
    ap.add_argument("--start", action="store_true", help="start canary at --percent")
    ap.add_argument("--tick", action="store_true", help="evaluate FP + expand or auto-hold")
    ap.add_argument("--hold", action="store_true", help="operator hold → percent 0")
    ap.add_argument("--expand", action="store_true", help="force one ladder step (green FP assumed)")
    ap.add_argument("--abort", action="store_true", help="emergency abort → shadow bundle")
    ap.add_argument("--status", action="store_true", help="show state + installed bundle")
    ap.add_argument("--percent", type=int, default=None, help="cohort percent for --start")
    ap.add_argument("--ladder-steps", default=None, help="comma ladder e.g. 0,5,25,100")
    ap.add_argument("--fp-slo-pct", type=float, default=None, help=f"session FP SLO %% (default {DEFAULT_FP_SLO_PCT})")
    ap.add_argument("--min-sessions", type=int, default=DEFAULT_MIN_SESSIONS)
    ap.add_argument("--sessions", type=int, default=None, help="injected sessions for --tick")
    ap.add_argument("--fp-sessions", type=int, default=None, help="injected FP sessions for --tick")
    ap.add_argument("--api-url", default=None, help="live API base for /api/security/fp-rate")
    ap.add_argument("--cookie-jar", default=None, help="Cookie header file for live API")
    ap.add_argument("--token", default=None, help="Bearer token (or AIM_API_TOKEN)")
    ap.add_argument("--days", type=int, default=7, help="FP rate window days for live API")
    ap.add_argument("--reason", default=None, help="note for start/hold/abort")
    ap.add_argument("--actor", default=os.environ.get("USER") or "ops")
    ap.add_argument("--state-dir", type=Path, default=None, help="default $AIM_STATE_DIR or ~/.aim-collector")
    ap.add_argument("--bundle-dir", type=Path, default=None, help="default deploy/enforcement")
    ap.add_argument("--managed", action="store_true", help="install to /etc/aim-collector/enforcement.json")
    ap.add_argument("--dry-run", action="store_true", help="decide without writing state/bundles")
    ap.add_argument("--json", action="store_true", help="machine-readable stdout")
    args = ap.parse_args()

    args.state_dir = args.state_dir or default_state_dir()
    args.bundle_dir = args.bundle_dir or default_bundle_dir()

    if args.self_test:
        return self_test()
    if args.ladder:
        sys.stdout.write(ladder_text())
        return 0
    if args.start:
        return cmd_start(args)
    if args.tick:
        return cmd_tick(args)
    if args.hold:
        return cmd_hold(args)
    if args.expand:
        return cmd_expand(args)
    if args.abort:
        return cmd_abort(args)
    if args.status:
        return cmd_status(args)

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
