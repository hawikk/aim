"""Discovery of GitHub Copilot on-disk surfaces — no network.

Surfaces (all local):

* VS Code / VSCodium / Cursor / remote-server extension dirs
  (``github.copilot`` and ``github.copilot-chat``)
* Matching ``globalStorage`` dirs (last-used mtime + chat session files)
* JetBrains plugin dirs (``github-copilot-intellij`` / ``com.github.copilot``)
* Copilot CLI home (``~/.copilot``) and ``copilot`` / ``gh`` on PATH

Env overrides (tests / relocated installs):

    AIM_COPILOT_HOME            treat as $HOME
    AIM_COPILOT_EXTENSION_DIR   extra VS Code extensions dir
    AIM_COPILOT_STORAGE_DIR     extra globalStorage/github.copilot* dir
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path

ENV_HOME = "AIM_COPILOT_HOME"
ENV_EXTENSION_DIR = "AIM_COPILOT_EXTENSION_DIR"
ENV_STORAGE_DIR = "AIM_COPILOT_STORAGE_DIR"

VSCODE_EXT_IDS = ("github.copilot", "github.copilot-chat")
_VSCODE_VARIANTS = ("Code", "Code - Insiders", "VSCodium", "Cursor")
_EXT_DIR_RE = re.compile(
    r"^(github\.copilot(?:-chat)?)-(\d+\.\d+\.\d+.*)$", re.IGNORECASE
)
_JB_PLUGIN_NAMES = ("github-copilot-intellij", "com.github.copilot")


def home() -> Path:
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override).expanduser()
    return Path.home()


def _user_data_dirs() -> list[Path]:
    """Candidate VS Code / Cursor user-data dirs (parent of globalStorage)."""
    h = home()
    dirs: list[Path] = []
    if sys.platform.startswith("win"):
        appdata = Path(os.environ.get("APPDATA", h / "AppData" / "Roaming"))
        dirs += [appdata / v / "User" for v in _VSCODE_VARIANTS]
    elif sys.platform == "darwin":
        base = h / "Library" / "Application Support"
        dirs += [base / v / "User" for v in _VSCODE_VARIANTS]
    else:
        xdg = Path(os.environ.get("XDG_CONFIG_HOME", h / ".config"))
        # When AIM_COPILOT_HOME is set, prefer that tree's .config first.
        dirs += [xdg / v / "User" for v in _VSCODE_VARIANTS]
        dirs += [h / ".config" / v / "User" for v in _VSCODE_VARIANTS]
        dirs += [
            h / ".vscode-server" / "data" / "User",
            h / ".vscode-server-insiders" / "data" / "User",
            h / ".cursor-server" / "data" / "User",
        ]
    return _dedupe_existing_parents(dirs)


def _dedupe_existing_parents(dirs: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for d in dirs:
        try:
            key = d.resolve()
        except OSError:
            key = d
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def extension_dirs() -> list[Path]:
    override = os.environ.get(ENV_EXTENSION_DIR)
    if override:
        return [Path(override).expanduser()]
    h = home()
    dirs = [
        h / ".vscode" / "extensions",
        h / ".vscode-insiders" / "extensions",
        h / ".vscode-server" / "extensions",
        h / ".vscodium" / "extensions",
        h / ".cursor" / "extensions",
        h / ".cursor-server" / "extensions",
    ]
    if sys.platform.startswith("win"):
        dirs.append(h / ".vscode" / "extensions")
    return dirs


def _version_key(v: str) -> tuple:
    parts = []
    for chunk in re.split(r"[.\-+]", v):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
    return tuple(parts)


def discover_extensions() -> list[dict]:
    """Installed Copilot VS Code-family extensions (no network).

    Each hit: {id, version, path}.
    """
    found: list[dict] = []
    seen: set[Path] = set()
    for ext_dir in extension_dirs():
        try:
            entries = list(ext_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                rc = entry.resolve()
            except OSError:
                rc = entry
            if rc in seen or not entry.is_dir():
                continue
            name = entry.name.lower()
            ext_id = None
            ver = None
            m = _EXT_DIR_RE.match(entry.name)
            if m:
                ext_id = m.group(1).lower()
                ver = m.group(2)
            else:
                for eid in VSCODE_EXT_IDS:
                    if name == eid or name.startswith(eid + "-"):
                        ext_id = eid
                        break
            if not ext_id:
                continue
            pkg = entry / "package.json"
            if pkg.is_file():
                try:
                    data = json.loads(pkg.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and data.get("version"):
                        ver = str(data["version"])
                    pid = data.get("name") if isinstance(data, dict) else None
                    pub = data.get("publisher") if isinstance(data, dict) else None
                    if isinstance(pub, str) and isinstance(pid, str):
                        ext_id = f"{pub}.{pid}".lower()
                except (OSError, json.JSONDecodeError):
                    pass
            seen.add(rc)
            found.append({"id": ext_id, "version": ver, "path": entry})
    # highest version per id
    best: dict[str, dict] = {}
    for hit in found:
        cur = best.get(hit["id"])
        if cur is None:
            best[hit["id"]] = hit
            continue
        cv = cur.get("version") or ""
        nv = hit.get("version") or ""
        if nv and (not cv or _version_key(nv) > _version_key(cv)):
            best[hit["id"]] = hit
    return list(best.values())


def extension_version(*, chat: bool = False) -> str | None:
    want = "github.copilot-chat" if chat else "github.copilot"
    for hit in discover_extensions():
        if hit["id"] == want and hit.get("version"):
            return str(hit["version"])
    # fall back to any discovered version
    for hit in discover_extensions():
        if hit.get("version"):
            return str(hit["version"])
    return None


def storage_dirs() -> list[Path]:
    """Existing github.copilot / github.copilot-chat globalStorage dirs."""
    override = os.environ.get(ENV_STORAGE_DIR)
    if override:
        p = Path(override).expanduser()
        return [p] if p.is_dir() else []
    out: list[Path] = []
    seen: set[Path] = set()
    for user in _user_data_dirs():
        gs = user / "globalStorage"
        for eid in VSCODE_EXT_IDS:
            cand = gs / eid
            try:
                if not cand.is_dir():
                    continue
                rc = cand.resolve()
            except OSError:
                continue
            if rc in seen:
                continue
            seen.add(rc)
            out.append(cand)
    return out


def settings_files() -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()
    for user in _user_data_dirs():
        p = user / "settings.json"
        try:
            if not p.is_file():
                continue
            rc = p.resolve()
        except OSError:
            continue
        if rc in seen:
            continue
        seen.add(rc)
        out.append(p)
    return out


def workspace_user_dirs() -> list[Path]:
    return [d for d in _user_data_dirs() if d.is_dir()]


def chat_session_files() -> list[Path]:
    """Chat-session JSON files. Names/ids only are used by the extractor."""
    files: list[Path] = []
    seen: set[Path] = set()

    def _take(p: Path) -> None:
        try:
            if not p.is_file() or p.suffix.lower() != ".json":
                return
            if p.name.lower() in _DENIED_BASENAMES:
                return
            rc = p.resolve()
        except OSError:
            return
        if rc in seen:
            return
        seen.add(rc)
        files.append(p)

    for storage in storage_dirs():
        sessions = storage / "chatSessions"
        if sessions.is_dir():
            try:
                for child in sessions.iterdir():
                    _take(child)
            except OSError:
                pass
        # some builds drop conversation JSON at the storage root
        try:
            for child in storage.iterdir():
                if child.is_file() and child.suffix == ".json":
                    _take(child)
        except OSError:
            pass

    for user in workspace_user_dirs():
        ws = user / "workspaceStorage"
        if not ws.is_dir():
            continue
        try:
            for wdir in ws.iterdir():
                sdir = wdir / "chatSessions"
                if not sdir.is_dir():
                    continue
                for child in sdir.iterdir():
                    _take(child)
        except OSError:
            continue
    return files


_DENIED_BASENAMES = frozenset(
    {
        "hosts.json",
        "token.json",
        "tokens.json",
        "secrets.json",
        "secretstorage.json",
        "storage.json",
    }
)


def jetbrains_plugin_dirs() -> list[Path]:
    h = home()
    roots: list[Path] = []
    if sys.platform.startswith("win"):
        local = Path(os.environ.get("LOCALAPPDATA", h / "AppData" / "Local"))
        roots.append(local / "JetBrains")
    elif sys.platform == "darwin":
        roots.append(h / "Library" / "Application Support" / "JetBrains")
    else:
        roots.append(h / ".local" / "share" / "JetBrains")
        roots.append(h / ".config" / "JetBrains")
    out: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for plugin_root in root.rglob("plugins"):
                if not plugin_root.is_dir():
                    continue
                for name in _JB_PLUGIN_NAMES:
                    cand = plugin_root / name
                    try:
                        if not cand.is_dir():
                            continue
                        rc = cand.resolve()
                    except OSError:
                        continue
                    if rc in seen:
                        continue
                    seen.add(rc)
                    out.append(cand)
        except OSError:
            continue
    return out


def jetbrains_option_files() -> list[Path]:
    h = home()
    roots: list[Path] = []
    if sys.platform.startswith("win"):
        roaming = Path(os.environ.get("APPDATA", h / "AppData" / "Roaming"))
        roots.append(roaming / "JetBrains")
    elif sys.platform == "darwin":
        roots.append(h / "Library" / "Application Support" / "JetBrains")
    else:
        roots.append(h / ".config" / "JetBrains")
    out: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for p in root.rglob("options"):
                if not p.is_dir():
                    continue
                for child in p.iterdir():
                    name = child.name.lower()
                    if not child.is_file():
                        continue
                    if "copilot" not in name:
                        continue
                    try:
                        rc = child.resolve()
                    except OSError:
                        continue
                    if rc in seen:
                        continue
                    seen.add(rc)
                    out.append(child)
        except OSError:
            continue
    return out


def cli_homes() -> list[Path]:
    h = home()
    cands = [
        h / ".copilot",
        h / ".config" / "github-copilot",
    ]
    out: list[Path] = []
    seen: set[Path] = set()
    for c in cands:
        try:
            if not c.is_dir():
                continue
            rc = c.resolve()
        except OSError:
            continue
        if rc in seen:
            continue
        seen.add(rc)
        out.append(c)
    return out


def cli_present() -> bool:
    if cli_homes():
        return True
    if shutil.which("copilot") is not None:
        return True
    return False


_CLI_DENIED = frozenset(
    {
        "hosts.json",
        "token.json",
        "tokens.json",
        "credentials.json",
        "apps.json",
    }
)


def cli_session_candidates() -> list[Path]:
    """JSON files under Copilot CLI homes that may carry session metadata.

    Auth/token files are excluded and never opened by the extractor.
    """
    out: list[Path] = []
    seen: set[Path] = set()
    for home_dir in cli_homes():
        try:
            for child in home_dir.rglob("*.json"):
                if not child.is_file():
                    continue
                if child.name.lower() in _CLI_DENIED:
                    continue
                if "token" in child.name.lower() or "secret" in child.name.lower():
                    continue
                try:
                    rc = child.resolve()
                except OSError:
                    continue
                if rc in seen:
                    continue
                seen.add(rc)
                out.append(child)
        except OSError:
            continue
    return out


def vscode_state_dbs() -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()
    for user in _user_data_dirs():
        for rel in (
            Path("globalStorage") / "state.vscdb",
            Path("state.vscdb"),
        ):
            p = user / rel
            try:
                if not p.is_file():
                    continue
                rc = p.resolve()
            except OSError:
                continue
            if rc in seen:
                continue
            seen.add(rc)
            out.append(p)
    return out


def any_surface_present() -> bool:
    if discover_extensions():
        return True
    if storage_dirs():
        return True
    if jetbrains_plugin_dirs():
        return True
    if cli_present():
        return True
    return False
