"""Register Kimi Code [[hooks]] in ~/.kimi-code/config.toml and enroll.

Official contract: blockable events are UserPromptSubmit and PreToolUse.
Exit 2 denies. We own a marked block in config.toml and leave the rest
of the file untouched.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import enroll, paths

_MARKER = "kimi_collector"
_MARKERS = ("kimi_collector", "aim hook")
_START = "# AIM-HOOK-START"
_END = "# AIM-HOOK-END"


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
    override = os.environ.get("AIM_KIMI_CONFIG")
    if override:
        return Path(override).expanduser()
    return paths.kimi_home() / "config.toml"


def _strip_ours(text: str) -> str:
    if _START not in text or _END not in text:
        return text
    before, rest = text.split(_START, 1)
    _, after = rest.split(_END, 1)
    return before.rstrip() + ("\n" if before.strip() else "") + after.lstrip("\n")


def _block(cmd: str) -> str:
    safe = cmd.replace("\\", "\\\\").replace('"', '\\"')
    return (
        f"{_START}\n"
        f"[[hooks]]\n"
        f"event = \"UserPromptSubmit\"\n"
        f"command = \"{safe}\"\n"
        f"timeout = 10\n"
        f"\n"
        f"[[hooks]]\n"
        f"event = \"PreToolUse\"\n"
        f"command = \"{safe}\"\n"
        f"timeout = 10\n"
        f"{_END}\n"
    )


def install() -> Path:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text() if path.exists() else ""
    body = _strip_ours(existing).rstrip()
    block = _block(_command())
    text = (body + "\n\n" + block) if body else block
    tmp = path.with_suffix(".toml.aim-tmp")
    tmp.write_text(text if text.endswith("\n") else text + "\n")
    os.replace(tmp, path)
    return path


def uninstall() -> Path:
    path = settings_path()
    if path.exists():
        text = _strip_ours(path.read_text())
        if text.strip():
            path.write_text(text if text.endswith("\n") else text + "\n")
        else:
            path.unlink()
    return path


def main(args: list) -> int:
    opts = enroll.parse_install_args(args)
    if opts is None:
        sys.stderr.write("usage: python -m kimi_collector "
                         + enroll.INSTALL_USAGE + "\n")
        return 2
    print(f"hooks registered in {install()}")
    return enroll.setup(opts)
