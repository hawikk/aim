"""MCP server config inventory for Claude Code (schema v1.2, AIM-97/AIM-570).

Reports which MCP servers are CONFIGURED — name and scope only, never
commands, args, URLs, or env values (env may hold secrets). One
``event_type="inventory"`` event is emitted when the sorted (name, scope)
set changes; a hash of the set is checkpointed so steady state emits nothing.

Sources (Claude Code config layout):

    ~/.claude.json  (override: AIM_CLAUDE_JSON)
        User-scope: top-level ``mcpServers`` object KEYS.
        Project-scope: ``projects.<path>.mcpServers`` object KEYS (user-
        configured for that project; path itself never leaves the endpoint).

    <project>/.mcp.json
        Project-scope checked-in / project-local MCP config, same shape.
        Project paths come from the keys of ``projects`` in ``~/.claude.json``
        plus optional session ``cwd`` values already in the checkpoint
        (never re-emitted).

Project scope wins name ties with user scope (same resolution posture as
Kilo/Kimi inventory). Missing/unreadable files yield an empty inventory
and never raise.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from . import events

_MAX_SERVERS = 200  # schema maxItems on configured_mcp_servers
PROJECT_MCP = Path(".mcp.json")


def claude_json_path() -> Path:
    """User-level Claude Code config (``~/.claude.json``)."""
    override = os.environ.get("AIM_CLAUDE_JSON")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".claude.json"


def _server_names_from_obj(data) -> list[str]:
    """Top-level ``mcpServers`` KEYS only — values never read. Never raises."""
    if not isinstance(data, dict):
        return []
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return []
    return [k.strip()[:128] for k in servers if isinstance(k, str) and k.strip()]


def _load_json(path: Path) -> dict | None:
    try:
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def collect(extra_workspaces: list[str] | None = None) -> list[dict]:
    """Sorted [{name, scope}] inventory. Project scope wins name ties."""
    by_name: dict[str, dict] = {}
    project_roots: set[str] = set()

    cfg = _load_json(claude_json_path())
    if cfg is not None:
        for name in _server_names_from_obj(cfg):
            by_name.setdefault(name, {"name": name, "scope": "user"})
        projects = cfg.get("projects")
        if isinstance(projects, dict):
            for path, pcfg in projects.items():
                if isinstance(path, str) and path.strip():
                    project_roots.add(path)
                if isinstance(pcfg, dict):
                    for name in _server_names_from_obj(pcfg):
                        by_name[name] = {"name": name, "scope": "project"}

    for ws in extra_workspaces or []:
        if isinstance(ws, str) and ws.strip():
            project_roots.add(ws)

    for root_path in project_roots:
        for name in _server_names_from_obj(_load_json(Path(root_path) / PROJECT_MCP) or {}):
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
