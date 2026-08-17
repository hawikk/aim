"""OS-aware path resolution for Cursor's local data.

Deployment targets are Windows (via Intune), WSL, and Linux. WSL reports
``sys.platform == "linux"`` and is therefore treated exactly like Linux.
macOS is out of scope for the pilot; the path is resolved best-effort.

Environment variable overrides exist for tests and deployment quirks:

- ``CURSOR_USER_DIR`` -- overrides the Cursor ``User/`` data directory.
- ``CURSOR_HOME``     -- overrides the ``~/.cursor`` directory.
"""

import os
import sys
from pathlib import Path

ENV_CURSOR_USER_DIR = "CURSOR_USER_DIR"
ENV_CURSOR_HOME = "CURSOR_HOME"


def cursor_user_dir() -> Path:
    """Return the Cursor ``User/`` data directory.

    Windows: ``%APPDATA%\\Cursor\\User``; Linux/WSL: ``~/.config/Cursor/User``;
    macOS (best effort): ``~/Library/Application Support/Cursor/User``.
    """
    override = os.environ.get(ENV_CURSOR_USER_DIR)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Cursor" / "User"
        return Path.home() / "AppData" / "Roaming" / "Cursor" / "User"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Cursor" / "User"
    return Path.home() / ".config" / "Cursor" / "User"


def cursor_home() -> Path:
    """Return the ``~/.cursor`` directory (hooks.json lives here)."""
    override = os.environ.get(ENV_CURSOR_HOME)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".cursor"


def hooks_json_path() -> Path:
    """User-level hooks file the collector manages. AIM_CURSOR_HOOKS_FILE
    overrides the whole path (tests/dev)."""
    override = os.environ.get("AIM_CURSOR_HOOKS_FILE")
    if override:
        return Path(override).expanduser()
    return cursor_home() / "hooks.json"


def global_state_db() -> Path:
    """The global state.vscdb (aiService.* keys)."""
    return cursor_user_dir() / "globalStorage" / "state.vscdb"


def workspace_state_dbs() -> list[Path]:
    """Per-workspace state.vscdb files (composer.* keys)."""
    root = cursor_user_dir() / "workspaceStorage"
    if not root.is_dir():
        return []
    return sorted(root.glob("*/state.vscdb"))
