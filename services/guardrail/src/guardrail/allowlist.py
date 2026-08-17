"""Scoped model/provider allowlist helpers (AIM-383 / AIM-326).

Two layers, both fail-open when empty:

1. **Policy-as-code** (``settings.approved_models`` / ``approved_providers`` /
   ``team_approved_models``) — evaluated per-event by the engine condition
   ``model_provider_not_permitted_for_scope``.
2. **Operational store** (``model_provider_allowlist`` table) — runtime
   overrides managed via the API. Missing/empty table for a scope = no
   restriction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class AllowlistEntry:
    scope_type: str  # global | team
    scope_id: str | None
    provider: str | None
    model: str | None
    mode: str  # observe | enforce
    enabled: bool = True


def entry_matches(entry: AllowlistEntry, provider: str | None, model: str | None) -> bool:
    if entry.provider is not None and entry.provider != provider:
        return False
    if entry.model is not None and entry.model != model:
        return False
    return True


def effective_entries(
    entries: Iterable[AllowlistEntry], team: str | None
) -> list[AllowlistEntry]:
    """Resolve team-over-global precedence. Empty result = no restriction."""
    enabled = [e for e in entries if e.enabled]
    if team:
        team_rows = [
            e for e in enabled if e.scope_type == "team" and e.scope_id == team
        ]
        if team_rows:
            return team_rows
    return [e for e in enabled if e.scope_type == "global"]


def is_permitted(
    entries: Iterable[AllowlistEntry],
    *,
    team: str | None,
    provider: str | None,
    model: str | None,
) -> tuple[bool, str]:
    """Return (permitted, reason). Fail-open when no allowlist is configured."""
    if provider is None and model is None:
        return True, "unobservable"
    effective = effective_entries(entries, team)
    if not effective:
        return True, "no_allowlist_configured"
    for entry in effective:
        if entry_matches(entry, provider, model):
            return True, f"matched:{entry.scope_type}:{entry.scope_id or '*'}"
    return False, "not_on_allowlist"


def max_mode(entries: Iterable[AllowlistEntry], team: str | None) -> str:
    effective = effective_entries(entries, team)
    if any(e.mode == "enforce" for e in effective):
        return "enforce"
    return "observe"


def load_allowlist(conn: Any) -> list[AllowlistEntry] | None:
    """Load enabled rows. Returns None if the table is missing."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT scope_type, scope_id, provider, model, mode, enabled
                FROM model_provider_allowlist
                WHERE enabled = true
                """
            )
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).lower()
        if "model_provider_allowlist" in msg or "does not exist" in msg or "undefinedtable" in msg:
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                pass
            return None
        raise
    return [
        AllowlistEntry(
            scope_type=r[0],
            scope_id=r[1],
            provider=r[2],
            model=r[3],
            mode=r[4] or "observe",
            enabled=bool(r[5]),
        )
        for r in rows
    ]
