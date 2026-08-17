"""Discovery of Kimi Code on-disk data (~/.kimi-code).

Kimi Code is a terminal CLI. It stores per-session telemetry under its
per-user home dir:

    ~/.kimi-code/
        session_index.jsonl                      # one JSON per line:
                                                 # {sessionId, sessionDir, workDir}
        sessions/<wd_dir>/session_<uuid>/
            state.json                           # session metadata; WARNING:
                                                 # `title`/`lastPrompt` carry
                                                 # full prompt text — read
                                                 # only safe keys locally
            agents/<agent>/wire.jsonl            # protocol wire log (content;
                                                 # local metadata scan only)
        updates/install.json                     # lastSuccess.version probe

``session_index.jsonl`` is safe metadata and is the primary session
directory; a filesystem walk of ``sessions/`` is the fallback for entries
missing from the index. Content-bearing files are never opened here.

Env override:
    AIM_KIMI_HOME  -- explicit Kimi Code home dir (tests/dev, relocated installs)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

ENV_KIMI_HOME = "AIM_KIMI_HOME"

DEFAULT_HOME = "~/.kimi-code"
SESSION_INDEX = "session_index.jsonl"

_MAX_INDEX_BYTES = 64 * 1024 * 1024


def kimi_home() -> Path:
    """Kimi Code home dir (env override or default). May not exist."""
    return Path(os.environ.get(ENV_KIMI_HOME, DEFAULT_HOME)).expanduser()


def _workdir_from_state(session_dir: Path) -> str | None:
    """Best-effort workDir from state.json. Reads ONLY the safe key; the
    file also carries `title`/`lastPrompt` prompt text, which is never
    returned, logged, or emitted."""
    try:
        data = json.loads((session_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    v = data.get("workDir")
    return v.strip() if isinstance(v, str) and v.strip() else None


def sessions() -> list[dict]:
    """Discovered sessions: [{"session_id", "session_dir", "work_dir"}].

    Primary source is session_index.jsonl; any session dirs on disk that the
    index misses are appended via the filesystem walk (workDir recovered
    from state.json). Never raises.
    """
    home = kimi_home()
    out: list[dict] = []
    seen: set[str] = set()

    index = home / SESSION_INDEX
    try:
        if index.is_file() and index.stat().st_size <= _MAX_INDEX_BYTES:
            for line in index.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict):
                    continue
                sid = rec.get("sessionId")
                sdir = rec.get("sessionDir")
                if not (isinstance(sid, str) and isinstance(sdir, str)):
                    continue
                p = Path(sdir)
                if not p.is_dir():
                    continue
                work_dir = rec.get("workDir")
                if not (isinstance(work_dir, str) and work_dir.strip()):
                    work_dir = _workdir_from_state(p)
                key = str(p.resolve()) if _resolvable(p) else str(p)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"session_id": sid, "session_dir": p,
                            "work_dir": work_dir if isinstance(work_dir, str) else None})
    except OSError:
        pass

    # Filesystem walk fallback: sessions/<wd_dir>/session_*/
    sessions_root = home / "sessions"
    try:
        wd_dirs = sorted(d for d in sessions_root.iterdir() if d.is_dir())
    except OSError:
        wd_dirs = []
    for wd in wd_dirs:
        try:
            session_dirs = sorted(d for d in wd.iterdir() if d.is_dir())
        except OSError:
            continue
        for p in session_dirs:
            key = str(p.resolve()) if _resolvable(p) else str(p)
            if key in seen:
                continue
            seen.add(key)
            out.append({"session_id": p.name, "session_dir": p,
                        "work_dir": _workdir_from_state(p)})
    return out


def _resolvable(p: Path) -> bool:
    try:
        p.resolve()
        return True
    except OSError:
        return False


def wire_files(session_dir: Path) -> list[Path]:
    """agents/*/wire.jsonl under a session dir. Never raises."""
    agents = session_dir / "agents"
    try:
        return sorted(
            f for f in agents.glob("*/wire.jsonl") if f.is_file()
        )
    except OSError:
        return []


def tool_version() -> str | None:
    """Best-effort installed Kimi Code version from updates/install.json
    (``lastSuccess.version``). None when not discoverable."""
    try:
        data = json.loads(
            (kimi_home() / "updates" / "install.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    v = (data.get("lastSuccess") or {}).get("version")
    return v.strip() if isinstance(v, str) and v.strip() else None
