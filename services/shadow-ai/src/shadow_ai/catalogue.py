"""AI-tool catalogue: the discovery knowledge base, as data.

Loading and matching only — the catalogue file (catalogue/ai-tools.json) is the
source of truth. Adding a newly-discovered AI SaaS is a catalogue entry, never
a code change (AIM-300 acceptance criterion 4).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DATA_ACCESS_CLASSES = {
    "code-context",
    "communication-data",
    "prompts-and-files",
    "model-api",
    "unknown",
}


@dataclass
class CatalogueTool:
    id: str
    name: str
    vendor: str
    sanctioned: bool
    data_access_class: str
    domains: list[str] = field(default_factory=list)
    oauth_client_ids: list[str] = field(default_factory=list)
    oauth_app_name_patterns: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class KnownNonAi:
    id: str
    name: str
    app_name_patterns: list[str] = field(default_factory=list)
    notes: str = ""


class Catalogue:
    def __init__(self, tools: list[CatalogueTool], known_non_ai: list[KnownNonAi]):
        self.tools = tools
        self.known_non_ai = known_non_ai
        self._by_client_id = {
            cid: t for t in tools for cid in t.oauth_client_ids
        }

    @classmethod
    def load(cls, path: str | Path) -> "Catalogue":
        raw = json.loads(Path(path).read_text())
        tools = []
        for t in raw.get("tools", []):
            dac = t.get("data_access_class", "unknown")
            if dac not in DATA_ACCESS_CLASSES:
                raise ValueError(f"catalogue tool {t.get('id')}: bad data_access_class {dac!r}")
            oauth = t.get("oauth", {})
            tools.append(
                CatalogueTool(
                    id=t["id"],
                    name=t["name"],
                    vendor=t.get("vendor", ""),
                    sanctioned=bool(t.get("sanctioned", False)),
                    data_access_class=dac,
                    domains=[d.lower() for d in t.get("domains", [])],
                    oauth_client_ids=list(oauth.get("client_ids", [])),
                    oauth_app_name_patterns=list(oauth.get("app_name_patterns", [])),
                    notes=t.get("notes", ""),
                )
            )
        known = [
            KnownNonAi(
                id=k["id"],
                name=k["name"],
                app_name_patterns=list(k.get("app_name_patterns", [])),
                notes=k.get("notes", ""),
            )
            for k in raw.get("known_non_ai", [])
        ]
        return cls(tools, known)

    def match_oauth_app(self, app_name: str, client_id: str | None) -> CatalogueTool | None:
        """Match an IdP OAuth grant to a catalogued tool.

        client_id exact match wins (stable across renames); fall back to
        case-insensitive substring match on the IdP app display name.
        When multiple patterns hit, the longest pattern wins so
        "Microsoft 365 Copilot" does not collapse into a shorter "copilot"
        entry.
        """
        if client_id and client_id in self._by_client_id:
            return self._by_client_id[client_id]
        name = (app_name or "").lower()
        if not name:
            return None
        best: CatalogueTool | None = None
        best_len = -1
        for tool in self.tools:
            for p in tool.oauth_app_name_patterns:
                pl = p.lower()
                if pl and pl in name and len(pl) > best_len:
                    best = tool
                    best_len = len(pl)
        return best

    def is_known_non_ai(self, app_name: str) -> bool:
        name = (app_name or "").lower()
        if not name:
            return False
        return any(
            p.lower() in name for k in self.known_non_ai for p in k.app_name_patterns
        )

    def match_domain(self, domain: str) -> CatalogueTool | None:
        """Suffix match, mirroring collectors/proxy endpoints.json semantics."""
        d = (domain or "").lower()
        if not d:
            return None
        for tool in self.tools:
            if any(d == dom or d.endswith("." + dom) for dom in tool.domains):
                return tool
        return None


def slugify(value: str) -> str:
    """Stable tool_id for uncatalogued apps, derived from the IdP app name."""
    slug = re.sub(r"[^a-z0-9]+", "_", (value or "").strip().lower()).strip("_")
    return slug[:64] or "unknown"
