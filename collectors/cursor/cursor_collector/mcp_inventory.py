"""MCP server config inventory for Cursor (schema v1.2, AIM-97/AIM-570).

Reports which MCP servers are CONFIGURED — name and scope only, never
commands, args, URLs, or env values. One ``event_type="inventory"`` event
is emitted when the sorted (name, scope) set changes; a hash of the set is
checkpointed so steady state emits nothing.

Sources:

    ~/.cursor/mcp.json  (via paths.cursor_home(); override CURSOR_HOME)
        User-scope config: ``{"mcpServers": {"<name>": {command/args/env...}}}``.

    <workspace>/.cursor/mcp.json
        Project-scope config, same shape. Project scope wins name ties.
        Workspace paths come from Cursor workspaceStorage ``workspace.json``
        folders (already resolved by the vscdb scanner) — never re-emitted.

Missing/unreadable files yield an empty inventory and never raise.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import events, paths

_MAX_SERVERS = 200
PROJECT_MCP = Path(".cursor") / "mcp.json"


def _server_names(path: Path) -> list[str]:
    """Top-level ``mcpServers`` KEYS only — values never read. Never raises."""
    try:
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return []
    return [k.strip()[:128] for k in servers if isinstance(k, str) and k.strip()]


def user_mcp_path() -> Path:
    return paths.cursor_home() / "mcp.json"


def collect(workspaces: list[str] | None = None) -> list[dict]:
    """Sorted [{name, scope}] inventory. Project scope wins name ties."""
    by_name: dict[str, dict] = {}
    for name in _server_names(user_mcp_path()):
        by_name.setdefault(name, {"name": name, "scope": "user"})
    for ws in workspaces or []:
        if not isinstance(ws, str) or not ws.strip():
            continue
        for name in _server_names(Path(ws) / PROJECT_MCP):
            by_name[name] = {"name": name, "scope": "project"}
    return sorted(by_name.values(), key=lambda e: e["name"])[:_MAX_SERVERS]


def scan(
    cp: dict,
    *,
    workspaces: list[str] | None = None,
    tool_version: str | None = None,
) -> dict | None:
    """Return an inventory event when the configured set changed, else None.

    Mutates ``cp["mcp_inventory"]`` with the new set hash after a valid event
    is built. Never raises.
    """
    try:
        servers = collect(workspaces)
        digest = hashlib.sha256(
            json.dumps(servers, separators=(",", ":")).encode()
        ).hexdigest()
        inv = cp.setdefault("mcp_inventory", {})
        if inv.get("hash") == digest:
            return None
        ev = events.new_inventory_event(
            configured_mcp_servers=servers, tool_version=tool_version)
        inv["hash"] = digest
        return ev
    except (ValueError, TypeError, OSError):
        return None
