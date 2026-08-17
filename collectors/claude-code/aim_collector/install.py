"""Install/uninstall hook registration in ~/.claude/settings.json.

Idempotent: our entries are tagged by command prefix; install rewrites only
our own entries and leaves every other setting untouched. Uses a file
backup before each mutation so a bad write is recoverable.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SETTINGS_PATH = "~/.claude/settings.json"

# Events we register for. PostToolUse remains the telemetry rail for tool
# calls (fire-and-forget). PreToolUse was added for AIM-110 Phase 1: it is
# the only hook that can DENY a tool call, and we need it to block MCP calls
# to unapproved servers. It spawns a process per tool call, so the hook does
# no telemetry work on this event — decision logic only, fail-open, and
# shadow mode by default until the enforcement gates clear.
HOOK_EVENTS = ("SessionStart", "SessionEnd", "PostToolUse", "UserPromptSubmit", "PreToolUse")

# Markers identifying a hook WE installed, regardless of how it was installed:
#   * "aim_collector" — the standalone/source default (`-m aim_collector hook`).
#   * "aim hook"      — the packaged `aim` CLI form (`-m aim hook claude-code`);
#                       a wheel vendors this collector under aim._vendor where it
#                       is NOT importable as a top-level module, so it must be
#                       serviced through `aim hook` (see aim.tools.hook_command).
# _MARKER stays the standalone default; detection accepts either so install /
# uninstall / status recognize hooks written by any install method.
_MARKER = "aim_collector"
_MARKERS = ("aim_collector", "aim hook")


def contains_our_hook(text: str) -> bool:
    """True if `text` (a settings-file blob or a command line) carries a hook
    command we installed, by any install method."""
    return any(m in text for m in _MARKERS)


def _command() -> str:
    """Hook command line. Default: the interpreter running `install`
    (`sys.executable`) — correct on Windows native (no `python3` on PATH),
    WSL, and Linux, and it pins the packaged interpreter in Intune
    deployments. AIM_HOOK_COMMAND overrides for custom wrappers."""
    override = os.environ.get("AIM_HOOK_COMMAND")
    if override:
        return override
    exe = sys.executable or "python3"
    if " " in exe:
        exe = f'"{exe}"'
    return f"{exe} -m {_MARKER} hook"


def settings_path() -> Path:
    return Path(os.environ.get("AIM_CLAUDE_SETTINGS", SETTINGS_PATH)).expanduser()


def _load(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _is_ours(hook: dict) -> bool:
    return isinstance(hook, dict) and contains_our_hook(str(hook.get("command", "")))


def install() -> Path:
    path = settings_path()
    cfg = _load(path)
    hooks = cfg.setdefault("hooks", {})
    cmd = _command()

    for event in HOOK_EVENTS:
        groups = [g for g in hooks.get(event, []) if isinstance(g, dict)]
        for g in groups:  # drop stale copies of ours
            g["hooks"] = [h for h in g.get("hooks", []) if not _is_ours(h)]
        groups = [g for g in groups if g.get("hooks")]
        groups.append({"hooks": [{"type": "command", "command": cmd}]})
        hooks[event] = groups

    _write(path, cfg)
    _record_tool_version()
    return path


def uninstall() -> Path:
    path = settings_path()
    cfg = _load(path)
    hooks = cfg.get("hooks", {})
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        for g in groups:
            if isinstance(g, dict):
                g["hooks"] = [h for h in g.get("hooks", []) if not _is_ours(h)]
        hooks[event] = [g for g in groups if isinstance(g, dict) and g.get("hooks")]
        if not hooks[event]:
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
        sys.stderr.write("usage: python -m aim_collector "
                         + enroll.INSTALL_USAGE + "\n")
        return 2
    print(f"hooks registered in {install()}")
    return enroll.setup(opts)


def _record_tool_version() -> None:
    from . import state
    try:
        out = subprocess.run(["claude", "--version"], capture_output=True,
                             text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            (state.state_dir() / "tool_version").write_text(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass  # absence is fine; events carry tool_version: null
