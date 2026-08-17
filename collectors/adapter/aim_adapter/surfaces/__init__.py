"""Extraction surface drivers.

Only a genuinely new surface type requires a new module here.
Adding a tool for an existing type is a manifest entry.
"""

from __future__ import annotations

from typing import Any, Callable

from . import editor_extension_hooks, local_session_logs, provider_api, proxy_domain

DRIVERS: dict[str, Any] = {
    "local_session_logs": local_session_logs,
    "editor_extension_hooks": editor_extension_hooks,
    "proxy_domain": proxy_domain,
    "provider_api": provider_api,
}


def get_driver(surface_type: str):
    try:
        return DRIVERS[surface_type]
    except KeyError as e:
        raise KeyError(
            f"unknown surface type {surface_type!r}; implement surfaces/{surface_type}.py"
        ) from e
