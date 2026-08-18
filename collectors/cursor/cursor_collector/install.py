"""Install/uninstall hook registration in ~/.cursor/hooks.json.

Cursor hooks file shape::

    {"version": 1, "hooks": {"sessionStart": [{"command": "..."}], ...}}

Idempotent: our entries are tagged by command marker; install rewrites only
our own entries and leaves every other entry (and the file's other keys)
untouched. A file backup is written before each mutation.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import hook, paths

# Markers identifying a hook WE installed, regardless of install method:
#   * "cursor_collector" — the standalone/source default.
#   * "aim hook"         — the packaged `aim` CLI form (`-m aim hook cursor …`),
#                          required for wheel installs (see aim.tools.hook_command).
_MARKER = "cursor_collector"
_MARKERS = ("cursor_collector", "aim hook")


def contains_our_hook(text: str) -> bool:
    """True if `text` carries a hook command we installed, by any install method."""
    return any(m in text for m in _MARKERS)


def _command(event: str) -> str:
    """Hook command line. Default: the interpreter running `install`
    (`sys.executable`) — correct on Windows native (no `python3` on PATH),
    WSL, and Linux, and it pins the packaged interpreter in Intune
    deployments. AIM_HOOK_COMMAND overrides for custom wrappers (the event
    name is appended)."""
    override = os.environ.get("AIM_HOOK_COMMAND")
    if override:
        return f"{override} {event}"
    exe = sys.executable or "python3"
    if " " in exe:
        exe = f'"{exe}"'
    return f"{exe} -m {_MARKER} hook {event}"


def settings_path() -> Path:
    return paths.hooks_json_path()


def _load(path: Path) -> dict:
    if path.exists():
        try:
            cfg = json.loads(path.read_text())
            if isinstance(cfg, dict):
                return cfg
        except json.JSONDecodeError:
            pass
    return {}


def _is_ours(entry: dict) -> bool:
    return isinstance(entry, dict) and contains_our_hook(str(entry.get("command", "")))


def install() -> Path:
    path = settings_path()
    cfg = _load(path)
    cfg.setdefault("version", 1)
    hooks = cfg.setdefault("hooks", {})

    for event in hook.HOOK_EVENTS:
        entries = [e for e in hooks.get(event, [])
                   if isinstance(e, dict) and not _is_ours(e)]
        entries.append({"command": _command(event)})
        hooks[event] = entries

    _write(path, cfg)
    _record_tool_version()
    return path


def uninstall() -> Path:
    path = settings_path()
    cfg = _load(path)
    hooks = cfg.get("hooks", {})
    if isinstance(hooks, dict):
        for event in list(hooks):
            entries = hooks[event]
            if not isinstance(entries, list):
                continue
            entries = [e for e in entries if isinstance(e, dict) and not _is_ours(e)]
            if entries:
                hooks[event] = entries
            else:
                del hooks[event]
    _write(path, cfg)
    return path


def _write(path: Path, cfg: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_suffix(".json.aim-bak"))
    tmp = path.with_suffix(".json.aim-tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n")
    os.replace(tmp, path)


def main(args: list) -> int:
    """One-line install UX (AIM-80): register hooks, then — when
    --ingest-url/--enroll-token are given — write config, enroll the
    device, and verify connectivity end-to-end."""
    from . import enroll
    opts = enroll.parse_install_args(args)
    if opts is None:
        sys.stderr.write("usage: python -m cursor_collector "
                         + enroll.INSTALL_USAGE + "\n")
        return 2
    print(f"hooks registered in {install()}")
    return enroll.setup(opts)


def _record_tool_version() -> None:
    from . import state
    try:
        out = subprocess.run(["cursor", "--version"], capture_output=True,
                             text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            (state.state_dir() / "tool_version").write_text(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass  # absence is fine; events carry no tool_version
