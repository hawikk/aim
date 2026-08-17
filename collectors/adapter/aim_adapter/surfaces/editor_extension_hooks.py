"""Surface: editor extension hooks / extension-id inventory.

Fidelity split:
  - extension id / package.json version → presence / inventory (this driver)
  - deep hook payloads (Claude PreToolUse, etc.) → legacy packages implementing
    the same contract; this driver does not re-implement those parsers.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DiscoveryResult:
    tool_id: str
    present: bool
    in_use: bool
    version: str | None
    surface: str
    evidence: str
    error: str | None = None
    paths: list[str] = field(default_factory=list)


def _extension_dirs(root: str | None = None) -> list[Path]:
    if root:
        base = Path(root)
        return [
            base / ".vscode" / "extensions",
            base / ".cursor" / "extensions",
        ]
    home = Path.home()
    dirs = [
        home / ".vscode" / "extensions",
        home / ".vscode-insiders" / "extensions",
        home / ".cursor" / "extensions",
    ]
    if os.name != "nt":
        dirs += [
            home / ".vscode-server" / "extensions",
            home / ".vscodium" / "extensions",
        ]
    return dirs


def discover(
    manifest: dict[str, Any],
    surface: dict[str, Any],
    *,
    root: str | None = None,
) -> DiscoveryResult:
    tool_id = manifest["id"]
    discovery = surface.get("discovery") or {}
    ext_ids = [e.lower() for e in (discovery.get("extension_ids") or [])]
    version: str | None = None
    found_paths: list[str] = []
    for ext_dir in _extension_dirs(root):
        if not ext_dir.is_dir():
            continue
        try:
            entries = list(ext_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            name = entry.name.lower()
            for eid in ext_ids:
                # VS Code layout: publisher.name-version
                if name == eid or name.startswith(eid + "-"):
                    found_paths.append(str(entry))
                    pkg = entry / "package.json"
                    if pkg.is_file():
                        try:
                            data = json.loads(pkg.read_text(encoding="utf-8"))
                            version = str(data.get("version") or version or "")
                        except (OSError, json.JSONDecodeError):
                            pass
    present = bool(found_paths)
    return DiscoveryResult(
        tool_id=tool_id,
        present=present,
        in_use=False,  # inventory only without hook stream
        version=version or None,
        surface="editor_extension_hooks",
        evidence=f"extensions={len(found_paths)}",
        paths=found_paths,
    )


def extract_rows(
    manifest: dict[str, Any],
    surface: dict[str, Any],
    *,
    root: str | None = None,
    records: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], int, list[str]]:
    """Hook depth is legacy; generic path emits inventory-style presence rows
    only when records are injected (tests) or extraction.format is not legacy.
    """
    extraction = surface.get("extraction") or {}
    if extraction.get("format") == "legacy":
        return [], 0, ["legacy: editor hook depth stays in hand-written collector"]
    if records is not None:
        return list(records), 0, []
    # Inventory-only: one row when extension is present (no usage depth)
    disc = discover(manifest, surface, root=root)
    if not disc.present:
        return [], 0, []
    return (
        [
            {
                "ts": None,
                "session_id": f"inventory:{manifest['id']}",
                "tool_version": disc.version,
                "model": None,
            }
        ],
        0,
        [],
    )
