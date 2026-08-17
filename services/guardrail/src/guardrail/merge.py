"""Multi-source policy pack merge (AIM-691).

Merges org + team + local guardrail packs into one effective ``Ruleset`` with
documented precedence and security floors.

See ``docs/security/multi-source-policy-merge.md`` for the operator contract.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from .rules import Ruleset, RulesetError, load_ruleset

# Ascending specificity. Later sources override earlier ones *except* where a
# security floor forbids weakening (see merge helpers below).
SOURCE_ORDER: tuple[str, ...] = ("org", "team", "local")

# Settings keys treated as allowlists: non-empty ∩ non-empty = intersection.
# Empty / missing at a layer means "no constraint from this layer" (inherit).
ALLOWLIST_KEYS: frozenset[str] = frozenset(
    {
        "approved_tools",
        "approved_mcp_servers",
        "approved_models",  # when a bare list (rare); map form handled specially
    }
)

# Settings keys treated as denylists / restricted sets: union across layers.
DENYLIST_KEYS: frozenset[str] = frozenset(
    {
        "restricted_repos",
        "blocked_tools",
        "blocked_mcp_servers",
        "blocked_providers",
        "blocked_models",
    }
)

# mcp_allowlist_mode: higher rank = more restrictive.
MCP_MODE_RANK: dict[str, int] = {
    "allow_unlisted": 0,
    "observe_unlisted": 1,
    "deny_unlisted": 2,
}

SEVERITY_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass
class PolicySource:
    """One named pack contribution."""

    name: str
    ruleset: Ruleset
    path: str | None = None


@dataclass
class MergeTrace:
    """Human-readable provenance for audits / tests."""

    sources: list[dict[str, Any]] = field(default_factory=list)
    rule_origins: dict[str, str] = field(default_factory=dict)
    rule_overrides_applied: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class MergedPolicy:
    ruleset: Ruleset
    trace: MergeTrace


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _content_hash_from_parts(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def _max_severity(a: str | None, b: str | None) -> str:
    left = str(a or "medium")
    right = str(b or "medium")
    ra = SEVERITY_RANK.get(left, 1)
    rb = SEVERITY_RANK.get(right, 1)
    return left if ra >= rb else right


def _merge_allowlist(base: list | None, overlay: list | None) -> list | None:
    """Intersection when both sides non-empty; empty side inherits the other."""
    if overlay is None:
        return copy.deepcopy(base) if base is not None else None
    if not isinstance(overlay, list):
        raise RulesetError(f"allowlist value must be a list, got {type(overlay).__name__}")
    if base is None or (isinstance(base, list) and len(base) == 0):
        return list(overlay)
    if len(overlay) == 0:
        return list(base)
    # Preserve order from base, keep only items also present in overlay.
    overlay_set = set(overlay)
    return [x for x in base if x in overlay_set]


def _merge_denylist(base: list | None, overlay: list | None) -> list:
    out: list[Any] = []
    seen: set[str] = set()
    for src in (base or [], overlay or []):
        if not isinstance(src, list):
            raise RulesetError(f"denylist value must be a list, got {type(src).__name__}")
        for item in src:
            key = _canonical_json(item) if isinstance(item, (dict, list)) else str(item)
            if key not in seen:
                seen.add(key)
                out.append(item)
    return out


def _merge_approved_providers(
    base: Mapping[str, Any] | None,
    overlay: Mapping[str, Any] | None,
) -> dict[str, list]:
    """Per-tool provider allowlists: intersection of lists when both set."""
    result: dict[str, list] = copy.deepcopy(dict(base or {}))
    if not overlay:
        return result
    for tool, providers in overlay.items():
        if not isinstance(providers, list):
            raise RulesetError(f"approved_providers[{tool!r}] must be a list")
        if tool not in result or not result[tool]:
            result[tool] = list(providers)
        elif not providers:
            continue  # empty overlay = inherit
        else:
            result[tool] = _merge_allowlist(list(result[tool]), providers) or []
    return result


def _merge_team_approved_models(
    base: Mapping[str, Any] | None,
    overlay: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """team_approved_models.<team>.<tool> = list → intersection per leaf list."""
    result: dict[str, Any] = copy.deepcopy(dict(base or {}))
    if not overlay:
        return result
    for team, tools in overlay.items():
        if not isinstance(tools, dict):
            result[team] = copy.deepcopy(tools)
            continue
        into = result.setdefault(team, {})
        if not isinstance(into, dict):
            result[team] = copy.deepcopy(tools)
            continue
        for tool, models in tools.items():
            if not isinstance(models, list):
                into[tool] = copy.deepcopy(models)
                continue
            existing = into.get(tool)
            if not isinstance(existing, list) or not existing:
                into[tool] = list(models)
            elif not models:
                continue
            else:
                into[tool] = _merge_allowlist(existing, models) or []
    return result


def _merge_mcp_mode(base: str | None, overlay: str | None) -> str | None:
    if overlay is None:
        return base
    if base is None:
        return overlay
    rb = MCP_MODE_RANK.get(str(base), -1)
    ro = MCP_MODE_RANK.get(str(overlay), -1)
    if rb < 0 and ro < 0:
        return overlay  # unknown → higher layer wins
    return base if rb >= ro else overlay


def _merge_enforcement(
    base: Mapping[str, Any] | None,
    overlay: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Deep-merge enforcement with enforce:true floor (cannot disable)."""
    result: dict[str, Any] = copy.deepcopy(dict(base or {}))
    if not overlay:
        return result
    for key, value in overlay.items():
        if key == "rules" and isinstance(value, dict):
            rules_into: dict[str, Any] = copy.deepcopy(result.get("rules") or {})
            for rid, ropts in value.items():
                if not isinstance(ropts, dict):
                    rules_into[rid] = copy.deepcopy(ropts)
                    continue
                cur = dict(rules_into.get(rid) or {})
                # Floor: once enforce is true, stay true.
                new_enforce = ropts.get("enforce", cur.get("enforce"))
                if cur.get("enforce") is True:
                    new_enforce = True
                cur.update(copy.deepcopy(ropts))
                if new_enforce is not None:
                    cur["enforce"] = new_enforce
                rules_into[rid] = cur
            result["rules"] = rules_into
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge_settings(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _deep_merge_settings(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Merge settings maps with allowlist/denylist/enforcement special cases."""
    result: dict[str, Any] = copy.deepcopy(dict(base))
    for key, value in overlay.items():
        if key in ALLOWLIST_KEYS:
            existing = result.get(key)
            if isinstance(existing, list) or existing is None:
                result[key] = _merge_allowlist(
                    existing if isinstance(existing, list) else None,
                    value if isinstance(value, list) else None,
                )
            else:
                # Non-list allowlist-shaped keys fall through to replace.
                result[key] = copy.deepcopy(value)
        elif key in DENYLIST_KEYS:
            existing = result.get(key)
            result[key] = _merge_denylist(
                existing if isinstance(existing, list) else None,
                value if isinstance(value, list) else None,
            )
        elif key == "approved_providers":
            result[key] = _merge_approved_providers(
                result.get(key) if isinstance(result.get(key), dict) else None,
                value if isinstance(value, dict) else None,
            )
        elif key == "team_approved_models":
            result[key] = _merge_team_approved_models(
                result.get(key) if isinstance(result.get(key), dict) else None,
                value if isinstance(value, dict) else None,
            )
        elif key == "approved_models" and isinstance(value, dict):
            # Map form: per-tool model allowlists → intersection.
            existing = result.get(key)
            if not isinstance(existing, dict):
                result[key] = copy.deepcopy(value)
            else:
                merged: dict[str, Any] = copy.deepcopy(existing)
                for tool, models in value.items():
                    if isinstance(models, list):
                        cur = merged.get(tool)
                        merged[tool] = _merge_allowlist(
                            cur if isinstance(cur, list) else None,
                            models,
                        )
                    else:
                        merged[tool] = copy.deepcopy(models)
                result[key] = merged
        elif key == "mcp_allowlist_mode":
            result[key] = _merge_mcp_mode(
                str(result[key]) if key in result and result[key] is not None else None,
                str(value) if value is not None else None,
            )
        elif key == "enforcement":
            result[key] = _merge_enforcement(
                result.get(key) if isinstance(result.get(key), dict) else None,
                value if isinstance(value, dict) else None,
            )
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge_settings(result[key], value)
        else:
            # Scalars / lists / replace: higher layer wins.
            result[key] = copy.deepcopy(value)
    return result


def _merge_threshold_fields(into: dict, overlay: dict) -> None:
    """Tighten threshold parameters: lower gt/gte and window_seconds win."""
    for key in ("gt", "gte"):
        if key in overlay and key in into:
            try:
                into[key] = min(float(into[key]), float(overlay[key]))
                if isinstance(into.get(key), float) and into[key].is_integer():
                    into[key] = int(into[key])
            except (TypeError, ValueError):
                into[key] = overlay[key]
        elif key in overlay:
            into[key] = overlay[key]
    # Mutually exclusive operators: if both end up set, keep the tighter bound
    # under a single operator (prefer gte when equal semantics unclear).
    if "gt" in into and "gte" in into:
        # Convert to gte with min effective bound.
        bound = min(float(into["gt"]), float(into["gte"]))
        into.pop("gt", None)
        into["gte"] = int(bound) if float(bound).is_integer() else bound
    if "window_seconds" in overlay and "window_seconds" in into:
        try:
            into["window_seconds"] = min(int(into["window_seconds"]), int(overlay["window_seconds"]))
        except (TypeError, ValueError):
            into["window_seconds"] = overlay["window_seconds"]
    elif "window_seconds" in overlay:
        into["window_seconds"] = overlay["window_seconds"]


def _merge_rule(base: dict, overlay: dict, overlay_source: str) -> dict:
    """Merge two rule bodies with severity floor + threshold tighten."""
    merged = copy.deepcopy(base)
    # Structural fields from higher layer (type/when/filter/group_by/metric).
    for key, value in overlay.items():
        if key in ("gt", "gte", "window_seconds", "severity"):
            continue
        merged[key] = copy.deepcopy(value)
    # Severity floor: cannot downgrade.
    merged["severity"] = _max_severity(base.get("severity"), overlay.get("severity"))
    if base.get("type") == "threshold" or overlay.get("type") == "threshold":
        _merge_threshold_fields(merged, overlay)
    merged["_source"] = overlay_source
    return merged


def _merge_rules(
    layers: list[PolicySource],
    trace: MergeTrace,
) -> list[dict]:
    by_id: dict[str, dict] = {}
    for layer in layers:
        for rule in layer.ruleset.rules:
            rid = rule["id"]
            if rid not in by_id:
                body = copy.deepcopy(rule)
                body["_source"] = layer.name
                by_id[rid] = body
                trace.rule_origins[rid] = layer.name
            else:
                prev = by_id[rid]
                by_id[rid] = _merge_rule(prev, rule, layer.name)
                trace.rule_origins[rid] = f"{trace.rule_origins[rid]}->{layer.name}"
                trace.notes.append(
                    f"rule {rid!r}: merged {prev.get('_source')} <- {layer.name} "
                    f"(severity floor + threshold tighten)"
                )
    # Stable order: first-seen across layers in SOURCE_ORDER, then id.
    order: list[str] = []
    seen: set[str] = set()
    for layer in layers:
        for rule in layer.ruleset.rules:
            rid = rule["id"]
            if rid not in seen:
                seen.add(rid)
                order.append(rid)
    return [by_id[rid] for rid in order]


def merge_policy_sources(sources: Iterable[PolicySource]) -> MergedPolicy:
    """Merge ordered policy sources into one effective ruleset.

    Sources must use names in ``SOURCE_ORDER``. Missing layers are fine.
    Duplicate names raise. Empty input raises.
    """
    by_name: dict[str, PolicySource] = {}
    for src in sources:
        if src.name not in SOURCE_ORDER:
            raise RulesetError(
                f"unknown policy source {src.name!r}; expected one of {SOURCE_ORDER}"
            )
        if src.name in by_name:
            raise RulesetError(f"duplicate policy source {src.name!r}")
        by_name[src.name] = src

    ordered = [by_name[n] for n in SOURCE_ORDER if n in by_name]
    if not ordered:
        raise RulesetError("no policy sources to merge")

    trace = MergeTrace()
    for src in ordered:
        trace.sources.append(
            {
                "name": src.name,
                "path": src.path,
                "content_hash": src.ruleset.content_hash,
                "version": src.ruleset.version,
                "rule_count": len(src.ruleset.rules),
            }
        )

    # Version: max across layers (materialised pack is at least the org floor).
    version = max(s.ruleset.version for s in ordered)

    settings: dict[str, Any] = {}
    for src in ordered:
        settings = _deep_merge_settings(settings, src.ruleset.settings)

    rules = _merge_rules(ordered, trace)

    # Strip internal provenance keys from engine-facing rule bodies (keep in
    # trace.rule_origins). Engine validates known fields only.
    clean_rules: list[dict] = []
    for rule in rules:
        body = {k: v for k, v in rule.items() if not k.startswith("_")}
        clean_rules.append(body)

    # content_hash covers every contributing layer hash + materialised body so
    # findings.policy_hash still fingerprints the *effective* policy.
    material = {
        "version": version,
        "settings": settings,
        "rules": clean_rules,
        "layers": [
            {"name": s.name, "content_hash": s.ruleset.content_hash} for s in ordered
        ],
    }
    content_hash = _content_hash_from_parts(_canonical_json(material))

    sources_list: list[str] = []
    for s in ordered:
        if s.path:
            sources_list.append(f"{s.name}:{s.path}")
        elif s.ruleset.sources:
            sources_list.extend(f"{s.name}:{p}" for p in s.ruleset.sources)
        else:
            sources_list.append(f"{s.name}:<memory>")

    ruleset = Ruleset(
        version=int(version),
        settings=settings,
        rules=clean_rules,
        content_hash=content_hash,
        sources=sources_list,
    )
    return MergedPolicy(ruleset=ruleset, trace=trace)


def load_policy_source(name: str, path: str | Path) -> PolicySource:
    """Load a single named pack directory/file via the standard ruleset loader."""
    rs = load_ruleset(path)
    return PolicySource(name=name, ruleset=rs, path=str(path))


def merge_policy_paths(
    *,
    org: str | Path | None = None,
    team: str | Path | None = None,
    local: str | Path | None = None,
) -> MergedPolicy:
    """Load and merge packs from optional filesystem paths."""
    sources: list[PolicySource] = []
    for name, path in (("org", org), ("team", team), ("local", local)):
        if path is None:
            continue
        p = Path(path)
        if not p.exists():
            raise RulesetError(f"policy source {name!r} path does not exist: {p}")
        sources.append(load_policy_source(name, p))
    return merge_policy_sources(sources)


def merge_policy_from_env(env: Mapping[str, str] | None = None) -> MergedPolicy:
    """Resolve pack paths from environment variables.

    | Env | Layer |
    |---|---|
    | ``GUARDRAIL_POLICY_ORG_PATH`` or ``GUARDRAIL_POLICY_PATH`` | org |
    | ``GUARDRAIL_POLICY_TEAM_PATH`` | team |
    | ``GUARDRAIL_POLICY_LOCAL_PATH`` | local |

    If only the legacy single-path env is set, behaviour matches a one-layer
    org pack (hash differs from ``load_ruleset`` because multi-source
    materialisation includes the layer list — use ``load_ruleset`` when you
    need byte-identical single-dir hashes).
    """
    import os

    e = env if env is not None else os.environ
    org = e.get("GUARDRAIL_POLICY_ORG_PATH") or e.get("GUARDRAIL_POLICY_PATH")
    team = e.get("GUARDRAIL_POLICY_TEAM_PATH") or None
    local = e.get("GUARDRAIL_POLICY_LOCAL_PATH") or None
    if not org and not team and not local:
        raise RulesetError(
            "no policy paths configured "
            "(set GUARDRAIL_POLICY_PATH / GUARDRAIL_POLICY_ORG_PATH "
            "and optional TEAM/LOCAL paths)"
        )
    return merge_policy_paths(org=org, team=team, local=local)


def effective_ruleset_from_paths(
    *,
    org: str | Path | None = None,
    team: str | Path | None = None,
    local: str | Path | None = None,
) -> Ruleset:
    """Convenience: return only the merged ``Ruleset``."""
    return merge_policy_paths(org=org, team=team, local=local).ruleset
