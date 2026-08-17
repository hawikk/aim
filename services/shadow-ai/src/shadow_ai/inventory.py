"""Inventory: correlate IdP grants + proxy observations + catalogue.

Output rows answer the AIM-300 acceptance criteria directly:
- tool, discovery source(s), first/last seen, identity count, OAuth scopes;
- risk score with per-component explanation;
- attribution stated honestly per source (proxy = unattributed by contract);
- uncatalogued apps surface as their own rows (catalogued=False) — that IS
  the discovery queue, not an error.

Known-non-AI apps (Slack, Zoom, Google first-party…) are suppressed so the
triage queue stays signal, not noise.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .catalogue import Catalogue, slugify
from .db import OAuthGrant, ToolInventoryRow, aware
from .proxy_source import ProxySource
from .risk import score_tool
from .scopes import classify_scopes


def build_inventory(session: Session, catalogue: Catalogue, proxy_source: ProxySource) -> list[ToolInventoryRow]:
    now = datetime.now(timezone.utc)
    rows: dict[str, dict] = {}

    # --- IdP OAuth grant signal (attributed) ---
    grants = session.execute(select(OAuthGrant)).scalars().all()
    active_by_tool: dict[str, set[str]] = defaultdict(set)
    for g in grants:
        tool = catalogue.match_oauth_app(g.app_name, g.client_id)
        if tool is None and catalogue.is_known_non_ai(g.app_name):
            continue  # expected non-AI SaaS — suppressed from the AI inventory
        key = tool.id if tool else slugify(g.app_name)
        row = rows.setdefault(key, _empty_row(key, g.app_name, tool))
        row["sources"].add("idp_oauth")
        row["first_seen"] = _min_dt(row["first_seen"], g.first_seen)
        row["last_seen"] = _max_dt(row["last_seen"], g.last_seen)
        if g.last_action == "revoke":
            # Revoked grants keep the row visible (the tool WAS in use) but
            # contribute no active identity and no scopes.
            continue
        row["scopes"].update(g.scopes)
        active_by_tool[key].add(g.user_pseudonym)

    # --- Proxy domain signal (unattributed, by contract) ---
    for obs in proxy_source.fetch():
        tool = catalogue.match_oauth_app(obs.tool_raw, None) or catalogue.match_domain(obs.tool_raw)
        key = tool.id if tool else slugify(obs.tool_raw)
        row = rows.setdefault(key, _empty_row(key, obs.tool_raw, tool))
        row["sources"].add("proxy_domain")
        row["proxy_host_count"] = obs.host_count
        row["first_seen"] = _min_dt(row["first_seen"], obs.first_seen)
        row["last_seen"] = _max_dt(row["last_seen"], obs.last_seen)

    # --- Materialize ---
    out: list[ToolInventoryRow] = []
    for key, r in rows.items():
        tool = r["tool"]
        catalogued = tool is not None
        identities = active_by_tool.get(key, set())
        has_idp = "idp_oauth" in r["sources"]
        has_proxy = "proxy_domain" in r["sources"]

        if has_idp and has_proxy:
            attribution = "partial"  # IdP rows attributed; proxy rows unattributable
        elif has_idp:
            attribution = "attributed"
        else:
            attribution = "unattributed"

        identity_count = len(identities) if has_idp else None
        scope_classes = classify_scopes(sorted(r["scopes"]))
        risk = score_tool(
            scope_classes=scope_classes,
            data_access_class=tool.data_access_class if tool else None,
            identity_count=identity_count,
            sanctioned=tool.sanctioned if tool else None,
            catalogued=catalogued,
        )
        sources = []
        if "idp_oauth" in r["sources"]:
            sources.append({"type": "idp_oauth", "attributed": True})
        if has_proxy:
            sources.append({"type": "proxy_domain", "attributed": False})

        out.append(
            ToolInventoryRow(
                tool_id=key,
                name=tool.name if tool else r["display_name"],
                vendor=tool.vendor if tool else None,
                catalogued=catalogued,
                sanctioned=tool.sanctioned if tool else None,
                data_access_class=tool.data_access_class if tool else None,
                sources=sources,
                attribution=attribution,
                identity_count=identity_count,
                scopes=sorted(r["scopes"]),
                scope_classes=scope_classes,
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                risk_score=risk["score"],
                risk_band=risk["band"],
                risk_components=risk["components"],
                computed_at=now,
            )
        )
    out.sort(key=lambda r: r.risk_score, reverse=True)
    return out


def persist_inventory(session: Session, rows: list[ToolInventoryRow]) -> None:
    """Replace the materialized inventory with the latest computation."""
    existing = {r.tool_id: r for r in session.execute(select(ToolInventoryRow)).scalars()}
    seen = set()
    for row in rows:
        seen.add(row.tool_id)
        if row.tool_id in existing:
            cur = existing[row.tool_id]
            for col in (
                "name", "vendor", "catalogued", "sanctioned", "data_access_class",
                "sources", "attribution", "identity_count", "scopes", "scope_classes",
                "first_seen", "last_seen", "risk_score", "risk_band",
                "risk_components", "computed_at",
            ):
                setattr(cur, col, getattr(row, col))
        else:
            session.add(row)
    for tool_id, cur in existing.items():
        if tool_id not in seen:
            session.delete(cur)
    session.commit()


def _empty_row(key: str, display_name: str, tool) -> dict:
    return {
        "tool": tool,
        "display_name": display_name,
        "sources": set(),
        "scopes": set(),
        "first_seen": None,
        "last_seen": None,
        "proxy_host_count": 0,
    }


def _min_dt(a, b):
    if a is None:
        return b
    return min(aware(a), aware(b))


def _max_dt(a, b):
    if a is None:
        return b
    return max(aware(a), aware(b))
