"""AI domain catalogue loader (data, not code).

Primary source: collectors/proxy/endpoints.json (AIM-19 detection DB).
Optional merge: shadow-AI discovery catalogue (AIM-300 ai-tools.json shape)
so newly discovered tools become coverage without a collector change.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Rule:
    id: str
    provider: str
    tool: str | None
    category: str | None
    sanctioned: bool
    domains: tuple[str, ...]

    def matches(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        for dom in self.domains:
            if h == dom or h.endswith("." + dom):
                return True
        return False


def load_endpoints(path: str | Path) -> list[Rule]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules: list[Rule] = []
    for raw in data.get("rules", []):
        domains = tuple(d.lower() for d in raw.get("domains") or [])
        if not domains:
            continue
        rules.append(
            Rule(
                id=raw["id"],
                provider=raw.get("provider") or "unknown",
                tool=raw.get("tool"),
                category=raw.get("category"),
                sanctioned=bool(raw.get("sanctioned")),
                domains=domains,
            )
        )
    return rules


def load_shadow_catalogue(path: str | Path) -> list[Rule]:
    """AIM-300 catalogue shape: {tools: [{id, domains, sanctioned, vendor, ...}]}."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules: list[Rule] = []
    for tool in data.get("tools") or []:
        domains = tuple(d.lower() for d in tool.get("domains") or [])
        if not domains:
            continue
        rules.append(
            Rule(
                id=f"shadow:{tool['id']}",
                provider=(tool.get("vendor") or tool["id"]).lower().replace(" ", "_")[:64],
                tool=tool["id"],
                category="web",
                sanctioned=bool(tool.get("sanctioned")),
                domains=domains,
            )
        )
    return rules


def merge_rules(*groups: Iterable[Rule]) -> list[Rule]:
    """Concatenate rules; match_rule uses longest domain so order is irrelevant."""
    out: list[Rule] = []
    for g in groups:
        out.extend(g)
    return out


def match_rule(rules: list[Rule], host: str) -> Rule | None:
    """Most specific (longest) matching domain wins — same semantics as proxy_ingest."""
    h = host.lower().rstrip(".")
    best: Rule | None = None
    best_len = -1
    for rule in rules:
        for dom in rule.domains:
            if (h == dom or h.endswith("." + dom)) and len(dom) > best_len:
                best = rule
                best_len = len(dom)
    return best
