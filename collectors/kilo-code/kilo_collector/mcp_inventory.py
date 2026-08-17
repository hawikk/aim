"""MCP server config inventory (AIM-97, schema v1.2).

Reports which MCP servers are CONFIGURED in Kilo Code — name and scope
only, never commands, args, URLs, or env values (env may hold secrets).
One ``event_type="inventory"`` event is emitted per scan in which the
sorted (name, scope) set changes; a hash of the set is checkpointed so
steady state emits nothing.

Sources:

    <globalStorage>/kilocode.kilo-code/settings/mcp_settings.json
        User-scope config: ``{"mcpServers": {"<name>": {command/args/env...}}}``.
        A ``settings/`` sibling of the ``tasks/`` dir the watcher walks.
    <workspace>/.kilocode/mcp.json
        Project-scope config, same shape. Project scope wins when a name is
        configured in both (Kilo's own resolution rule: project overrides
        user). Workspace paths are reused from the per-task checkpoint
        fragments (extracted from api_conversation_history.json
        environment_details blocks by tasks.py) — no extra parsing pass and
        no workspace path ever lands on an event.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import events

GLOBAL_SETTINGS = Path("settings") / "mcp_settings.json"
PROJECT_CONFIG = Path(".kilocode") / "mcp.json"
_MAX_SERVERS = 200  # schema maxItems on configured_mcp_servers


def _server_names(path: Path) -> list[str]:
    """Top-level ``mcpServers`` KEYS only — values (command/args/env/URL)
    are never read into the result. Never raises."""
    try:
        if path.stat().st_size > 1024 * 1024:
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return []
    return [k.strip()[:128] for k in servers if isinstance(k, str) and k.strip()]


def collect(storage_dirs, workspaces) -> list[dict]:
    """Sorted [{name, scope}] inventory across all config sources.
    Project scope wins name ties with user scope."""
    by_name: dict[str, dict] = {}
    for storage in storage_dirs:
        for name in _server_names(Path(storage) / GLOBAL_SETTINGS):
            by_name.setdefault(name, {"name": name, "scope": "user"})
    for ws in workspaces:
        for name in _server_names(Path(ws) / PROJECT_CONFIG):
            by_name[name] = {"name": name, "scope": "project"}
    return sorted(by_name.values(), key=lambda e: e["name"])[:_MAX_SERVERS]


def scan(cp: dict, storage_dirs, workspaces, tool_version: str | None = None) -> dict | None:
    """Return an inventory event when the configured set changed since the
    last scan, else None. Mutates ``cp["mcp_inventory"]`` with the new set
    hash; the caller persists the checkpoint."""
    servers = collect(storage_dirs, workspaces)
    digest = hashlib.sha256(
        json.dumps(servers, separators=(",", ":")).encode()
    ).hexdigest()
    inv = cp.setdefault("mcp_inventory", {})
    if inv.get("hash") == digest:
        return None
    inv["hash"] = digest
    try:
        return events.new_inventory_event(
            configured_mcp_servers=servers, tool_version=tool_version)
    except (ValueError, TypeError):
        return None
