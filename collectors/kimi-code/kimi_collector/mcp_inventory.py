"""MCP server config inventory (schema v1.2).

Reads the MCP server section of the Kimi Code user config
(``~/.kimi-code/config.toml``) and reports the configured server NAMES —
nothing else. The CLI's own config parser keys MCP servers under a
``mcpServers`` table (verified against the shipped binary); the plausible
alternative spellings are accepted too. Commands, args, URLs, and env
values in those tables are NEVER read into events or the checkpoint: only
the table keys (server names) are extracted, each capped to the schema's
128 chars, scope always "user" (config.toml is the user-level config; Kimi
Code has no project-level MCP config file).

Emission is change-only: the checkpoint stores a hash of the sorted name
set and one ``event_type="inventory"`` event is emitted when it differs
(including first observation — an empty set is an explicit 'no servers
configured' statement, which the schema allows). When the config file is
absent or unparseable, or the interpreter lacks ``tomllib`` (Python <
3.11), inventory is skipped quietly — never raises.
"""

from __future__ import annotations

import hashlib
import logging

from . import events, paths

log = logging.getLogger(__name__)

try:
    import tomllib
except ImportError:  # Python < 3.11: degrade gracefully, skip inventory
    tomllib = None

CONFIG_NAME = "config.toml"

# Candidate locations of the MCP server table, most likely first. The
# shipped binary parses ``mcpServers`` (camelCase); the others are
# defensive spellings. ``mcp.servers`` covers a ``[mcp]`` table with a
# nested ``servers`` sub-table.
_MCP_TABLE_PATHS = (("mcpServers",), ("mcp_servers",), ("mcp", "servers"))

_MAX_SERVERS = 200  # schema maxItems


def _server_names(cfg: dict) -> list[str]:
    """Sorted MCP server names (table KEYS only) from a parsed config."""
    for path in _MCP_TABLE_PATHS:
        node = cfg
        for k in path:
            node = node.get(k) if isinstance(node, dict) else None
        if isinstance(node, dict):
            names = sorted(
                k.strip()[:128] for k in node if isinstance(k, str) and k.strip()
            )
            return names[:_MAX_SERVERS]
    return []


def configured_servers() -> list[str] | None:
    """Sorted MCP server names from the user config, or None when no
    inventory can be taken (config missing/unreadable, or tomllib
    unavailable). Never raises."""
    if tomllib is None:
        log.info("tomllib unavailable (Python < 3.11); skipping MCP inventory")
        return None
    try:
        raw = (paths.kimi_home() / CONFIG_NAME).read_bytes()
    except OSError:
        return None
    try:
        cfg = tomllib.loads(raw.decode("utf-8"))
    except Exception:  # TOMLDecodeError / UnicodeDecodeError: treat as absent
        log.warning("could not parse %s; skipping MCP inventory", CONFIG_NAME)
        return None
    if not isinstance(cfg, dict):
        return None
    return _server_names(cfg)


def scan(cp: dict, tool_version: str | None = None) -> dict | None:
    """Emit one inventory event when the configured server set changed.

    ``cp`` is the loaded checkpoint dict; the name-set hash lives under the
    ``mcp_inventory`` key. Returns the event, or None when unchanged or
    inventory is unavailable. Never raises.
    """
    names = configured_servers()
    if names is None:
        return None
    digest = hashlib.sha256("\n".join(names).encode()).hexdigest()
    frag = cp.setdefault("mcp_inventory", {})
    if frag.get("hash") == digest:
        return None
    ev = events.new_inventory_event(
        configured_mcp_servers=[{"name": n, "scope": "user"} for n in names],
        tool_version=tool_version,
    )
    frag["hash"] = digest  # advance only after the event validated
    return ev
