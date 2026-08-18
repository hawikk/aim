"""Register Copilot / VS Code user hooks and (optionally) enroll.

Official user hook dir is ``~/.copilot/hooks/*.json`` (Copilot CLI and
VS Code agent hooks). We own ``aim.json`` in that folder.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import enroll

_MARKER = "copilot_collector"
_MARKERS = ("copilot_collector", "aim hook")


def contains_our_hook(text: str) -> bool:
    return any(m in text for m in _MARKERS)


def _command() -> str:
    override = os.environ.get("AIM_HOOK_COMMAND")
    if override:
        return override
    exe = sys.executable or "python3"
    if " " in exe:
        exe = f'"{exe}"'
    return f"{exe} -m {_MARKER} hook"


def settings_path() -> Path:
    override = os.environ.get("AIM_COPILOT_HOOKS_FILE")
    if override:
        return Path(override).expanduser()
    # AIM_COPILOT_HOME is $HOME (same convention as paths.py).
    home_override = os.environ.get("AIM_COPILOT_HOME")
    if home_override:
        return Path(home_override).expanduser() / ".copilot" / "hooks" / "aim.json"
    # Official Copilot CLI: $COPILOT_HOME/hooks when set.
    copilot_home = os.environ.get("COPILOT_HOME")
    if copilot_home:
        return Path(copilot_home).expanduser() / "hooks" / "aim.json"
    return Path.home() / ".copilot" / "hooks" / "aim.json"


def install() -> Path:
    path = settings_path()
    cmd = _command()
    entry = {
        "type": "command",
        "command": cmd,
        "bash": cmd,
        "powershell": cmd,
        "timeout": 10,
        "timeoutSec": 10,
    }
    # Register both PascalCase (VS Code) and camelCase (Copilot CLI).
    cfg = {
        "version": 1,
        "hooks": {
            "UserPromptSubmit": [entry],
            "userPromptSubmitted": [dict(entry)],
            "PreToolUse": [dict(entry)],
            "preToolUse": [dict(entry)],
        },
    }
    _write(path, cfg)
    return path


def uninstall() -> Path:
    path = settings_path()
    if path.exists() and contains_our_hook(path.read_text()):
        path.unlink()
    return path


def _write(path: Path, cfg: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.aim-tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n")
    os.replace(tmp, path)


def main(args: list) -> int:
    opts = enroll.parse_install_args(args)
    if opts is None:
        sys.stderr.write("usage: python -m copilot_collector "
                         + enroll.INSTALL_USAGE + "\n")
        return 2
    print(f"hooks registered in {install()}")
    return enroll.setup(opts)
