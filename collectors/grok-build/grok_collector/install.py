"""Register Grok Build user hooks under ~/.grok/hooks/ and enroll.

Official xAI path is ``~/.grok/hooks/*.json``. PreToolUse is the only
blocking event. We own ``aim.json``.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import enroll
from . import usage

_MARKER = "grok_collector"
_MARKERS = ("grok_collector", "aim hook")


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
    override = os.environ.get("AIM_GROK_HOOKS_FILE")
    if override:
        return Path(override).expanduser()
    return usage.grok_home() / "hooks" / "aim.json"


def install() -> Path:
    path = settings_path()
    cmd = _command()
    hook = {"type": "command", "command": cmd, "timeout": 10}
    # Omit matcher to match every tool name (official xAI contract).
    cfg = {
        "hooks": {
            "PreToolUse": [
                {"hooks": [hook]},
            ],
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.aim-tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n")
    os.replace(tmp, path)
    return path


def uninstall() -> Path:
    path = settings_path()
    if path.exists() and contains_our_hook(path.read_text()):
        path.unlink()
    return path


def main(args: list) -> int:
    opts = enroll.parse_install_args(args)
    if opts is None:
        sys.stderr.write("usage: python -m grok_collector "
                         + enroll.INSTALL_USAGE + "\n")
        return 2
    print(f"hooks registered in {install()}")
    return enroll.setup(opts)
