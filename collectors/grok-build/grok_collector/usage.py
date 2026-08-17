"""Resolve Grok token totals from local metadata-only logs.

Source of truth: ``~/.grok/logs/unified.jsonl`` lines with
``msg == "shell.turn.inference_done"``. Those records carry only numeric
usage counters (prompt_tokens, completion_tokens, …) plus session id / pid —
never prompt or response content.

Two consumption paths:

1. **Continuous log tail** (primary): ``scan_inference_log`` advances a
   byte offset and returns per-session token *deltas* for newly observed turns.
   This is what ``aim watch`` / ``scan-once`` use so all local Grok usage is
   counted — not only Paperclip heartbeats.
2. **Per-run correlation** (opt-in): ``resolve_tokens_for_run`` sums
   turns for a Paperclip run via env session id, process tree, or workspace
   time window. Used when ``AIM_GROK_RUN_TOKEN_RESOLVE=1`` or explicit token
   env/CLI overrides are set. Prefer continuous tail to avoid double-counting.

Token mapping (same posture as Kimi/Kilo collectors):

- ``tokens_in``      = sum(prompt_tokens)           # full prompt volume
- ``tokens_out``     = sum(completion_tokens)       # reasoning_tokens is a subset
- ``tokens_cached``  = sum(cached_prompt_tokens)    # subset of prompt; cost only

Cost estimates bill uncached input + cached input + output at xAI
list rates via ``pricing.estimate_cost``; volume fields stay full prompt.

Never opens ``chat_history.jsonl``, ``prompt_context.json``, or any content
log. Never contacts xAI APIs.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import quote


# How far back (bytes) to scan unified.jsonl when matching PIDs / sessions.
# Full-file scan is used when session ids are known and the log is small.
_LOG_TAIL_BYTES_PID = 8 * 1024 * 1024
_LOG_TAIL_BYTES_SESSION = 32 * 1024 * 1024
_SESSION_TIME_WINDOW_S = 15 * 60
_INFERENCE_MSG = "shell.turn.inference_done"
# Checkpoint key for continuous tail offsets (path → byte offset).
_CP_LOG_OFFSETS = "log_offsets"


@dataclass(frozen=True)
class TokenTotals:
    tokens_in: int
    tokens_out: int
    session_ids: tuple[str, ...]
    turns: int
    source: str  # env | process_tree | workspace_time | none
    tokens_cached: int = 0

    def as_optional(self) -> tuple[int | None, int | None]:
        if self.turns <= 0 and self.tokens_in <= 0 and self.tokens_out <= 0:
            return None, None
        return self.tokens_in, self.tokens_out


@dataclass(frozen=True)
class SessionDelta:
    """Per-Grok-session token delta from newly tailed inference_done lines."""

    session_id: str
    tokens_in: int
    tokens_out: int
    turns: int
    last_ts_epoch: float | None = None
    source: str = "log_tail"
    tokens_cached: int = 0

def grok_home() -> Path:
    override = (os.environ.get("AIM_GROK_HOME") or os.environ.get("GROK_HOME") or "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".grok"


def unified_log_path(home: Path | None = None) -> Path:
    return (home or grok_home()) / "logs" / "unified.jsonl"


def _env(name: str) -> str | None:
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else None


def _parse_session_ids_env() -> list[str]:
    raw = _env("AIM_GROK_SESSION_ID") or _env("GROK_SESSION_ID")
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def _env_token_overrides() -> tuple[int | None, int | None]:
    """Explicit totals from env (adapter/wrapper can set these)."""
    tin = _env("AIM_GROK_TOKENS_IN") or _env("GROK_TOKENS_IN")
    tout = _env("AIM_GROK_TOKENS_OUT") or _env("GROK_TOKENS_OUT")
    try:
        tokens_in = int(tin) if tin is not None else None
    except ValueError:
        tokens_in = None
    try:
        tokens_out = int(tout) if tout is not None else None
    except ValueError:
        tokens_out = None
    return tokens_in, tokens_out


def _encode_session_cwd(cwd: str) -> str:
    """Match Grok's session directory naming (URL-encoded absolute path)."""
    norm = os.path.abspath(os.path.expanduser(cwd))
    # Grok encodes the full absolute path with urllib-style percent encoding.
    return quote(norm, safe="")


def session_root_for_workspace(workspace: str, home: Path | None = None) -> Path:
    return (home or grok_home()) / "sessions" / _encode_session_cwd(workspace)


def _parse_iso_epoch(value: str | None) -> float | None:
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    # Accept "Z" suffix
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        from datetime import datetime
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def list_workspace_sessions(
    workspace: str,
    *,
    home: Path | None = None,
    around_epoch_s: float | None = None,
    window_s: float = _SESSION_TIME_WINDOW_S,
) -> list[str]:
    """Return session ids under a workspace, optionally filtered by created_at."""
    root = session_root_for_workspace(workspace, home=home)
    if not root.is_dir():
        return []
    out: list[tuple[float, str]] = []
    try:
        children = list(root.iterdir())
    except OSError:
        return []
    for child in children:
        if not child.is_dir():
            continue
        summary = child / "summary.json"
        created = None
        if summary.is_file():
            try:
                meta = json.loads(summary.read_text())
            except (OSError, json.JSONDecodeError):
                meta = {}
            if isinstance(meta, dict):
                created = _parse_iso_epoch(meta.get("created_at"))
                # Prefer id from summary when present
                info = meta.get("info") if isinstance(meta.get("info"), dict) else {}
                sid = (info.get("id") if isinstance(info, dict) else None) or child.name
            else:
                sid = child.name
        else:
            sid = child.name
            try:
                created = summary.stat().st_mtime if summary.is_file() else child.stat().st_mtime
            except OSError:
                created = None
        if around_epoch_s is not None and created is not None:
            if abs(created - around_epoch_s) > window_s:
                # Also accept sessions created after the run start within window
                if not (0 <= (created - around_epoch_s) <= window_s):
                    continue
        out.append((created or 0.0, str(sid)))
    out.sort(key=lambda x: x[0], reverse=True)
    return [sid for _, sid in out]


def process_ancestor_pids(start_pid: int | None = None) -> list[int]:
    """Walk /proc parent chain from start_pid (default: self)."""
    pid = start_pid if start_pid is not None else os.getpid()
    seen: set[int] = set()
    ordered: list[int] = []
    while pid and pid > 1 and pid not in seen:
        seen.add(pid)
        ordered.append(pid)
        try:
            status = (Path("/proc") / str(pid) / "status").read_text()
        except OSError:
            break
        ppid = None
        for line in status.splitlines():
            if line.startswith("PPid:"):
                try:
                    ppid = int(line.split()[1])
                except (IndexError, ValueError):
                    ppid = None
                break
        if ppid is None or ppid <= 1:
            break
        pid = ppid
    return ordered


def _is_grok_process(pid: int) -> bool:
    """True if /proc/<pid> looks like the Grok Build CLI binary."""
    try:
        status = (Path("/proc") / str(pid) / "status").read_text()
    except OSError:
        return False
    name = ""
    for line in status.splitlines():
        if line.startswith("Name:"):
            name = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
            break
    if name in ("grok", "grok-build"):
        return True
    try:
        cmd = (Path("/proc") / str(pid) / "cmdline").read_bytes().replace(b"\0", b" ")
        text = cmd.decode("utf-8", "replace")
    except OSError:
        return False
    # Avoid matching random paths that merely contain "grok" as a workspace name
    base = text.strip().split()
    if not base:
        return False
    prog = os.path.basename(base[0])
    return prog in ("grok", "grok-build") or prog.startswith("grok-")


def nearest_grok_pids(start_pid: int | None = None) -> list[int]:
    """Return the closest Grok CLI ancestor of start_pid (inclusive).

    Stops at the first Grok process so we do not attribute unrelated outer
    interactive Grok sessions that merely parent the Paperclip server.
    """
    for pid in process_ancestor_pids(start_pid):
        if _is_grok_process(pid):
            return [pid]
    return []


def pids_for_paperclip_run(run_id: str) -> list[int]:
    """Find nearest Grok CLI PIDs for processes with PAPERCLIP_RUN_ID=run_id."""
    if not run_id:
        return []
    proc = Path("/proc")
    if not proc.is_dir():
        return []
    matched: list[int] = []
    try:
        entries = list(proc.iterdir())
    except OSError:
        return []
    needle = f"PAPERCLIP_RUN_ID={run_id}".encode()
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "environ").read_bytes()
        except OSError:
            continue
        if needle not in raw:
            continue
        try:
            matched.append(int(entry.name))
        except ValueError:
            continue
    pids: list[int] = []
    seen: set[int] = set()
    for pid in matched:
        for p in nearest_grok_pids(pid):
            if p not in seen:
                seen.add(p)
                pids.append(p)
        # Also keep the agent process itself in case logs ever key on it.
        if pid not in seen:
            seen.add(pid)
            pids.append(pid)
    return pids


def _iter_log_lines(path: Path, *, max_bytes: int | None) -> Iterable[str]:
    if not path.is_file():
        return
    try:
        size = path.stat().st_size
    except OSError:
        return
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            if max_bytes is not None and size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()  # drop partial first line
            yield from f
    except OSError:
        return


def sum_tokens_for_sessions(
    session_ids: Iterable[str],
    *,
    log_path: Path | None = None,
    max_bytes: int | None = _LOG_TAIL_BYTES_SESSION,
) -> TokenTotals:
    wanted = {s for s in session_ids if s}
    if not wanted:
        return TokenTotals(0, 0, tuple(), 0, "none")
    path = log_path or unified_log_path()
    tokens_in = 0
    tokens_out = 0
    tokens_cached = 0
    turns = 0
    seen_sids: set[str] = set()
    for line in _iter_log_lines(path, max_bytes=max_bytes):
        # Cheap prefilter before JSON parse
        if _INFERENCE_MSG not in line:
            continue
        # Any wanted sid substring?
        if not any(sid in line for sid in wanted):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("msg") != _INFERENCE_MSG:
            continue
        sid = rec.get("sid")
        if not isinstance(sid, str) or sid not in wanted:
            continue
        ctx = rec.get("ctx")
        if not isinstance(ctx, dict):
            continue
        try:
            prompt = int(ctx.get("prompt_tokens") or 0)
            completion = int(ctx.get("completion_tokens") or 0)
            cached = int(ctx.get("cached_prompt_tokens") or 0)
        except (TypeError, ValueError):
            continue
        tokens_in += max(prompt, 0)
        tokens_out += max(completion, 0)
        tokens_cached += max(min(cached, prompt), 0) if prompt > 0 else max(cached, 0)
        turns += 1
        seen_sids.add(sid)
    return TokenTotals(
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        session_ids=tuple(sorted(seen_sids)),
        turns=turns,
        source="log",
        tokens_cached=tokens_cached,
    )


def session_ids_for_pids(
    pids: Iterable[int],
    *,
    log_path: Path | None = None,
    max_bytes: int | None = _LOG_TAIL_BYTES_PID,
) -> list[str]:
    wanted = {int(p) for p in pids}
    if not wanted:
        return []
    path = log_path or unified_log_path()
    found: set[str] = set()
    for line in _iter_log_lines(path, max_bytes=max_bytes):
        if _INFERENCE_MSG not in line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("msg") != _INFERENCE_MSG:
            continue
        try:
            pid = int(rec.get("pid"))
        except (TypeError, ValueError):
            continue
        if pid not in wanted:
            continue
        sid = rec.get("sid")
        if isinstance(sid, str) and sid:
            found.add(sid)
    return sorted(found)


def resolve_tokens_for_run(
    *,
    run_id: str | None = None,
    workspace_path: str | None = None,
    ts_epoch_s: float | None = None,
    home: Path | None = None,
    log_path: Path | None = None,
    prefer_process_tree: bool = True,
) -> TokenTotals:
    """Best-effort token totals for a Paperclip/Grok run.

    Priority:
    1. Explicit AIM_GROK_TOKENS_IN/OUT env
    2. Explicit AIM_GROK_SESSION_ID + log sum
    3. Process-tree PID match (self or run_id processes)
    4. Workspace session dir + time window
    """
    home = home or grok_home()
    log_path = log_path or unified_log_path(home)

    env_in, env_out = _env_token_overrides()
    if env_in is not None or env_out is not None:
        return TokenTotals(
            tokens_in=int(env_in or 0),
            tokens_out=int(env_out or 0),
            session_ids=tuple(_parse_session_ids_env()),
            turns=1 if (env_in or env_out) else 0,
            source="env",
        )

    # Explicit session ids
    env_sids = _parse_session_ids_env()
    if env_sids:
        totals = sum_tokens_for_sessions(env_sids, log_path=log_path)
        return TokenTotals(
            totals.tokens_in,
            totals.tokens_out,
            totals.session_ids,
            totals.turns,
            "env_session",
            tokens_cached=totals.tokens_cached,
        )

    # Process tree → nearest Grok CLI only (do not walk past into outer sessions)
    if prefer_process_tree:
        pids: list[int] = []
        if run_id:
            pids = pids_for_paperclip_run(run_id)
        if not pids:
            pids = nearest_grok_pids()
        sids = session_ids_for_pids(pids, log_path=log_path)
        # When workspace is known, drop sessions that do not belong to it.
        if sids and workspace_path:
            ws_sids = set(
                list_workspace_sessions(workspace_path, home=home, around_epoch_s=None)
            )
            if ws_sids:
                filtered = [s for s in sids if s in ws_sids]
                if filtered:
                    sids = filtered
        if sids:
            totals = sum_tokens_for_sessions(sids, log_path=log_path)
            if totals.turns > 0:
                return TokenTotals(
                    totals.tokens_in,
                    totals.tokens_out,
                    totals.session_ids,
                    totals.turns,
                    "process_tree",
                    tokens_cached=totals.tokens_cached,
                )

    # Workspace + time
    if workspace_path:
        around = ts_epoch_s if ts_epoch_s is not None else time.time()
        sids = list_workspace_sessions(
            workspace_path, home=home, around_epoch_s=around
        )
        # Prefer the single closest session in the window (one Paperclip run
        # ≈ one Grok session). Avoid summing concurrent sibling heartbeats.
        if sids:
            totals = sum_tokens_for_sessions(sids[:1], log_path=log_path)
            if totals.turns > 0:
                return TokenTotals(
                    totals.tokens_in,
                    totals.tokens_out,
                    totals.session_ids,
                    totals.turns,
                    "workspace_time",
                    tokens_cached=totals.tokens_cached,
                )

    return TokenTotals(0, 0, tuple(), 0, "none")


def _backfill_bytes_default() -> int:
    """Bytes of historical log to read on first sight of a log path.

    Default 0 = start at EOF (only new usage after collector upgrade). Set
    ``AIM_GROK_LOG_BACKFILL_BYTES`` (e.g. 33554432) for a one-shot catch-up
    without replaying multi-GB histories into the dashboard.
    """
    raw = _env("AIM_GROK_LOG_BACKFILL_BYTES")
    if raw is None:
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _parse_inference_turn(
    line: str,
) -> tuple[str, int, int, int, float | None] | None:
    """Return (sid, prompt, completion, cached_prompt, ts_epoch) or None.

    Metadata only — ignores any content-bearing fields if present.
    """
    if _INFERENCE_MSG not in line:
        return None
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    if rec.get("msg") != _INFERENCE_MSG:
        return None
    sid = rec.get("sid")
    if not isinstance(sid, str) or not sid:
        return None
    ctx = rec.get("ctx")
    if not isinstance(ctx, dict):
        return None
    try:
        prompt = int(ctx.get("prompt_tokens") or 0)
        completion = int(ctx.get("completion_tokens") or 0)
        cached = int(ctx.get("cached_prompt_tokens") or 0)
    except (TypeError, ValueError):
        return None
    if prompt < 0:
        prompt = 0
    if completion < 0:
        completion = 0
    if cached < 0:
        cached = 0
    if cached > prompt:
        cached = prompt
    ts_epoch = _parse_iso_epoch(rec.get("ts") if isinstance(rec.get("ts"), str) else None)
    return sid, prompt, completion, cached, ts_epoch


def scan_inference_log(
    cp: dict,
    *,
    log_path: Path | None = None,
    backfill_bytes: int | None = None,
) -> list[SessionDelta]:
    """Tail ``unified.jsonl`` and return per-session token deltas.

    Advances ``cp["log_offsets"][path]`` to the end of what was read. On first
    sight of a path, seeks to ``max(0, size - backfill_bytes)`` so a fresh
    install does not dump multi-month histories into dashboards unless an
    operator explicitly sets a backfill window.

    Safe under log rotation: if the file shrank below the stored offset, the
    offset resets to 0 (or size-backfill when backfill is configured).
    """
    path = log_path or unified_log_path()
    path_key = str(path)
    if not path.is_file():
        return []

    try:
        size = path.stat().st_size
    except OSError:
        return []

    offsets = cp.setdefault(_CP_LOG_OFFSETS, {})
    if not isinstance(offsets, dict):
        offsets = {}
        cp[_CP_LOG_OFFSETS] = offsets

    bf = _backfill_bytes_default() if backfill_bytes is None else max(0, int(backfill_bytes))
    if path_key not in offsets:
        start = max(0, size - bf) if bf > 0 else size
        offsets[path_key] = start
    else:
        try:
            start = int(offsets[path_key])
        except (TypeError, ValueError):
            start = 0
        if start > size:
            # Rotated/truncated
            start = max(0, size - bf) if bf > 0 else 0
            offsets[path_key] = start
        elif start < 0:
            start = 0

    if start >= size:
        return []

    # sid -> [tin, tout, turns, last_ts, cached]
    agg: dict[str, list] = {}
    new_offset = start
    try:
        # Binary mode so tell()/seek() stay reliable (text iterators disable
        # tell() after next() on some Python builds).
        with path.open("rb") as f:
            if start <= 0:
                f.seek(0)
            else:
                # Land on a line boundary: if start is mid-line (backfill /
                # rotation cut), skip the partial remainder. If start came
                # from a prior tell() it is already a boundary — keep it.
                f.seek(start - 1)
                prev = f.read(1)
                if prev != b"\n":
                    f.readline()
            new_offset = f.tell()
            while True:
                raw = f.readline()
                if not raw:
                    break
                new_offset = f.tell()
                try:
                    line = raw.decode("utf-8", "replace")
                except Exception:
                    continue
                parsed = _parse_inference_turn(line)
                if not parsed:
                    continue
                sid, prompt, completion, cached, ts_epoch = parsed
                row = agg.get(sid)
                if row is None:
                    agg[sid] = [prompt, completion, 1, ts_epoch, cached]
                else:
                    row[0] += prompt
                    row[1] += completion
                    row[2] += 1
                    row[4] += cached
                    if ts_epoch is not None and (
                        row[3] is None or ts_epoch >= row[3]
                    ):
                        row[3] = ts_epoch
    except OSError:
        return []

    offsets[path_key] = new_offset
    out: list[SessionDelta] = []
    for sid, (tin, tout, turns, last_ts, cached) in sorted(agg.items()):
        if turns <= 0 and tin <= 0 and tout <= 0:
            continue
        out.append(
            SessionDelta(
                session_id=sid,
                tokens_in=int(tin),
                tokens_out=int(tout),
                turns=int(turns),
                last_ts_epoch=last_ts,
                source="log_tail",
                tokens_cached=int(cached),
            )
        )
    return out
