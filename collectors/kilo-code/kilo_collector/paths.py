"""Discovery of Kilo Code on-disk data — IDE extension + standalone CLI.

## IDE surface (VS Code extension)

Kilo Code is a VS Code extension (Roo Code/Cline lineage, extension id
``kilocode.kilo-code``). It stores per-task telemetry under the extension's
``globalStorageUri``:

    <VS Code user-data>/globalStorage/kilocode.kilo-code/tasks/<taskId>/
        ui_messages.json               # UI events incl. per-request token/cost
        api_conversation_history.json  # API messages (content; local scan only)

Base paths per OS (Kilo Code docs, file-locations.md):
    Linux:   ~/.config/Code/User/globalStorage/kilocode.kilo-code/
    macOS:   ~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/
    Windows: %APPDATA%\\Code\\User\\globalStorage\\kilocode.kilo-code\\

Variants (Insiders, VSCodium, Cursor) and remote extension hosts
(``.vscode-server``, ``.cursor-server``) use their own user-data dirs; the
JetBrains wrapper uses ``~/.kilocode/globalStorage/``. The extension setting
``kilo-code.customStoragePath`` can relocate everything -- handled via the
AIM_KILO_STORAGE_DIR override (deployed per-fleet if needed).

## CLI surface (standalone ``kilo`` binary)

The same product family ships a standalone CLI (``~/.kilo/bin/kilo``) that
writes sessions to an XDG SQLite DB — **not** VS Code globalStorage:

    Linux/macOS:  $XDG_DATA_HOME/kilo/kilo.db  (default ~/.local/share/kilo/)
    Windows:      %LOCALAPPDATA%\\kilo\\kilo.db

Scanned by ``cli_sessions.py``. Events use ``tool_version`` prefix ``cli/``
so pilot dashboards can prove both surfaces.

Env overrides:
    AIM_KILO_STORAGE_DIR  -- explicit kilocode.kilo-code globalStorage dir
    AIM_KILO_EXTENSION_DIR -- explicit VS Code extensions dir (version probe)
    AIM_KILO_CLI_DB       -- explicit path to kilo.db (CLI surface)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path

ENV_STORAGE_DIR = "AIM_KILO_STORAGE_DIR"
ENV_EXTENSION_DIR = "AIM_KILO_EXTENSION_DIR"
ENV_CLI_DB = "AIM_KILO_CLI_DB"

EXT_STORAGE_NAME = "kilocode.kilo-code"
_VSCODE_VARIANTS = ("Code", "Code - Insiders", "VSCodium", "Cursor")


def _user_data_dirs() -> list[Path]:
    """Candidate VS Code / Cursor user-data dirs (parent of globalStorage)."""
    dirs: list[Path] = []
    if sys.platform.startswith("win"):
        appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        dirs += [appdata / v / "User" for v in _VSCODE_VARIANTS]
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
        dirs += [base / v / "User" for v in _VSCODE_VARIANTS]
    else:
        xdg = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        dirs += [xdg / v / "User" for v in _VSCODE_VARIANTS]
        # Remote extension hosts (SSH / WSL / dev containers) — VS Code + Cursor
        dirs += [
            Path.home() / ".vscode-server" / "data" / "User",
            Path.home() / ".vscode-server-insiders" / "data" / "User",
            Path.home() / ".cursor-server" / "data" / "User",
        ]
    return dirs


def storage_dirs() -> list[Path]:
    """Existing kilocode.kilo-code globalStorage dirs, in priority order."""
    override = os.environ.get(ENV_STORAGE_DIR)
    if override:
        p = Path(override).expanduser()
        return [p] if p.is_dir() else []
    candidates = [d / "globalStorage" / EXT_STORAGE_NAME for d in _user_data_dirs()]
    if not sys.platform.startswith("win"):
        # JetBrains wrapper
        candidates.append(
            Path.home() / ".kilocode" / "globalStorage" / EXT_STORAGE_NAME
        )
    seen: set[Path] = set()
    out: list[Path] = []
    for c in candidates:
        try:
            rc = c.resolve()
        except OSError:
            continue
        if rc in seen or not c.is_dir():
            continue
        seen.add(rc)
        out.append(c)
    return out


def task_dirs(storage: Path) -> list[Path]:
    """Per-task dirs under a globalStorage root. Never raises."""
    tasks = storage / "tasks"
    try:
        return sorted(p for p in tasks.iterdir() if p.is_dir())
    except OSError:
        return []


_VERSION_DIR_RE = re.compile(r"^kilocode\.kilo-code-(\d+\.\d+\.\d+.*)$")


def _extension_dirs() -> list[Path]:
    override = os.environ.get(ENV_EXTENSION_DIR)
    if override:
        return [Path(override).expanduser()]
    if sys.platform.startswith("win"):
        return [Path.home() / ".vscode" / "extensions"]
    dirs = [
        Path.home() / ".vscode" / "extensions",
        Path.home() / ".vscode-insiders" / "extensions",
        Path.home() / ".vscode-server" / "extensions",
        Path.home() / ".vscodium" / "extensions",
        # Cursor desktop + remote SSH host both host the Kilo extension
        Path.home() / ".cursor" / "extensions",
        Path.home() / ".cursor-server" / "extensions",
    ]
    return dirs


def extension_version() -> str | None:
    """Best-effort installed extension version from the extensions dir.

    Picks the highest ``kilocode.kilo-code-<version>/package.json`` found.
    Returns None when not discoverable (e.g. JetBrains-only / CLI-only).
    """
    best: str | None = None
    for ext_dir in _extension_dirs():
        try:
            entries = list(ext_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            m = _VERSION_DIR_RE.match(entry.name)
            if not m:
                continue
            ver = m.group(1)
            pkg = entry / "package.json"
            try:
                data = json.loads(pkg.read_text(encoding="utf-8"))
                ver = str(data.get("version") or ver)
            except (OSError, json.JSONDecodeError):
                pass
            if best is None or _version_key(ver) > _version_key(best):
                best = ver
    return best


def cli_db_paths() -> list[Path]:
    """Existing standalone Kilo CLI ``kilo.db`` paths (AIM-647 dual surface)."""
    override = os.environ.get(ENV_CLI_DB)
    if override:
        p = Path(override).expanduser()
        return [p] if p.is_file() else []
    candidates: list[Path] = []
    if sys.platform.startswith("win"):
        local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        candidates.append(local / "kilo" / "kilo.db")
    else:
        xdg_data = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        candidates.append(xdg_data / "kilo" / "kilo.db")
        # Some installs also keep state under ~/.kilo/
        candidates.append(Path.home() / ".kilo" / "kilo.db")
    seen: set[Path] = set()
    out: list[Path] = []
    for c in candidates:
        try:
            rc = c.resolve()
        except OSError:
            continue
        if rc in seen or not c.is_file():
            continue
        seen.add(rc)
        out.append(c)
    return out


def cli_present() -> bool:
    """True when the standalone Kilo CLI is installed or has local state."""
    if cli_db_paths():
        return True
    if shutil.which("kilo") is not None:
        return True
    return (Path.home() / ".kilo" / "bin" / "kilo").is_file()


def cli_version() -> str | None:
    """Best-effort CLI version from ``~/.kilo/package.json`` plugin pin."""
    pkg = Path.home() / ".kilo" / "package.json"
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    deps = data.get("dependencies") if isinstance(data, dict) else None
    if not isinstance(deps, dict):
        return None
    for key in ("@kilocode/plugin", "kilo", "@kilocode/cli"):
        ver = deps.get(key)
        if isinstance(ver, str) and ver.strip():
            return ver.strip().lstrip("^~=")
    return None


def any_surface_present() -> bool:
    """IDE storage and/or CLI install — used by ``aim`` detect."""
    return bool(storage_dirs()) or cli_present()


def _version_key(v: str) -> tuple:
    parts = []
    for chunk in re.split(r"[.\-+]", v):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
    return tuple(parts)
