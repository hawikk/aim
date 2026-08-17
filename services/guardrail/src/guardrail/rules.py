"""Ruleset loading, validation, and content hashing.

A ruleset is one or more YAML files in a directory (policy-as-code). The whole
ruleset is hashed so every finding and audit record can be tied back to the
exact policy revision that produced it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .conditions import ATTR_OPS, KNOWN_ATTRS, KNOWN_OPS

RULE_TYPES = ("match", "threshold")
SEVERITIES = ("low", "medium", "high", "critical")
THRESHOLD_METRICS = ("count", "sum_tokens", "sum_cost_usd")  # plus "sum:<field>"
# Top-level `rule_overrides` (UI-tuned thresholds) may touch only these.
OVERRIDE_KEYS = ("gt", "gte", "window_seconds", "severity")


class RulesetError(ValueError):
    pass


def _validate_condition_tree(tree, where: str) -> None:
    """Fail fast on malformed condition trees at load time.

    An unknown op or malformed leaf would otherwise only surface at runtime as
    a per-event audit 'error' — the rule silently dead while everything looks
    deployed (adversarial finding: policy laundering via a typo'd
    policy file).
    """
    if not isinstance(tree, dict):
        raise RulesetError(f"{where}: condition tree must be a mapping")
    if "all" in tree or "any" in tree:
        key = "all" if "all" in tree else "any"
        subs = tree[key]
        if not isinstance(subs, list) or not subs:
            raise RulesetError(f"{where}: '{key}' must be a non-empty list")
        for sub in subs:
            _validate_condition_tree(sub, where)
        return
    # ABAC attribute leaves (attr: user|group|repo_class|tool).
    if "attr" in tree:
        if "field" in tree:
            raise RulesetError(f"{where}: leaf cannot set both 'field' and 'attr'")
        attr = tree.get("attr")
        if attr not in KNOWN_ATTRS:
            raise RulesetError(
                f"{where}: unknown attr {attr!r} (known: {sorted(KNOWN_ATTRS)})"
            )
        ops = [k for k in tree if k != "attr"]
        if len(ops) != 1:
            raise RulesetError(f"{where}: attr condition needs exactly one op: {tree}")
        if ops[0] not in ATTR_OPS:
            raise RulesetError(
                f"{where}: attr op {ops[0]!r} not allowed (allowed: {sorted(ATTR_OPS)})"
            )
        return
    field_name = tree.get("field")
    if not field_name or not isinstance(field_name, str):
        raise RulesetError(f"{where}: leaf condition missing string 'field' or 'attr'")
    ops = [k for k in tree if k != "field"]
    if len(ops) != 1:
        raise RulesetError(f"{where}: leaf condition needs exactly one op: {tree}")
    if ops[0] not in KNOWN_OPS:
        raise RulesetError(f"{where}: unknown op {ops[0]!r} (known: {sorted(KNOWN_OPS)})")


@dataclass
class Ruleset:
    version: int
    settings: dict
    rules: list[dict]
    content_hash: str
    sources: list[str] = field(default_factory=list)


def _validate_rule(rule: dict, idx: int, source: str) -> None:
    where = f"{source}: rule[{idx}]"
    rid = rule.get("id")
    if not rid or not isinstance(rid, str):
        raise RulesetError(f"{where} missing string 'id'")
    rtype = rule.get("type")
    if rtype not in RULE_TYPES:
        raise RulesetError(f"{where} ({rid}): type must be one of {RULE_TYPES}")
    sev = rule.get("severity", "medium")
    if sev not in SEVERITIES:
        raise RulesetError(f"{where} ({rid}): severity must be one of {SEVERITIES}")
    if rtype == "match":
        if not isinstance(rule.get("when"), dict):
            raise RulesetError(f"{where} ({rid}): match rule needs a 'when' condition tree")
        _validate_condition_tree(rule["when"], f"{where} ({rid})")
    else:
        for key in ("group_by", "window_seconds", "metric"):
            if key not in rule:
                raise RulesetError(f"{where} ({rid}): threshold rule missing '{key}'")
        if not isinstance(rule["group_by"], list) or not rule["group_by"]:
            raise RulesetError(f"{where} ({rid}): group_by must be a non-empty list")
        if not isinstance(rule["window_seconds"], int) or rule["window_seconds"] <= 0:
            raise RulesetError(f"{where} ({rid}): window_seconds must be a positive int")
        metric = rule["metric"]
        if metric not in THRESHOLD_METRICS and not str(metric).startswith("sum:"):
            raise RulesetError(f"{where} ({rid}): unknown metric {metric!r}")
        if "gt" not in rule and "gte" not in rule:
            raise RulesetError(f"{where} ({rid}): threshold rule needs 'gt' or 'gte'")
        if "gt" in rule and "gte" in rule:
            raise RulesetError(f"{where} ({rid}): 'gt' and 'gte' are mutually exclusive")
        if "filter" in rule:
            if not isinstance(rule["filter"], dict):
                raise RulesetError(f"{where} ({rid}): filter must be a condition tree")
            _validate_condition_tree(rule["filter"], f"{where} ({rid})")


def _merge_rule_overrides(into: dict, data: dict, source: str) -> None:
    """Merge one file's top-level `rule_overrides` into the accumulated map.

    Per-rule dict update, later file wins per key (same precedence spirit as
    settings); cross-file conflicts are validated when the overrides are
    applied.
    """
    overrides = data.get("rule_overrides") or {}
    if not isinstance(overrides, dict):
        raise RulesetError(f"{source}: 'rule_overrides' must be a mapping of rule id to overrides")
    for rid, override in overrides.items():
        if not isinstance(override, dict):
            raise RulesetError(f"{source}: rule_overrides[{rid!r}] must be a mapping")
        into.setdefault(rid, {}).update(override)


def _validate_override(rid: str, override: dict) -> None:
    for key, value in override.items():
        if key not in OVERRIDE_KEYS:
            raise RulesetError(
                f"rule_overrides[{rid!r}]: unknown override key {key!r} (allowed: {OVERRIDE_KEYS})"
            )
        if key in ("gt", "gte"):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise RulesetError(f"rule_overrides[{rid!r}]: {key} must be a positive number")
        elif key == "window_seconds":
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise RulesetError(f"rule_overrides[{rid!r}]: window_seconds must be an integer >= 1")
        elif value not in SEVERITIES:  # severity
            raise RulesetError(f"rule_overrides[{rid!r}]: severity must be one of {SEVERITIES}")
    if "gt" in override and "gte" in override:
        raise RulesetError(f"rule_overrides[{rid!r}]: 'gt' and 'gte' are mutually exclusive")


def _apply_rule_overrides(rules: list[dict], rule_overrides: dict) -> None:
    """Apply merged overrides to the loaded rules in place, before the Engine
    compiles them. Fails loud on unknown ids, bad keys/values, and overrides
    targeting match rules."""
    by_id = {rule["id"]: rule for rule in rules}
    for rid, override in rule_overrides.items():
        rule = by_id.get(rid)
        if rule is None:
            raise RulesetError(f"rule_overrides targets unknown rule id {rid!r}")
        if rule.get("type") != "threshold":
            raise RulesetError(f"rule_overrides[{rid!r}]: overrides only apply to threshold rules")
        _validate_override(rid, override)
        # gt and gte are mutually exclusive threshold operators: overriding
        # one clears the other so the rule never ends up with both.
        if "gt" in override:
            rule.pop("gte", None)
        if "gte" in override:
            rule.pop("gt", None)
        rule.update(override)


def load_ruleset(path: str | Path) -> Ruleset:
    """Load and validate every *.yaml/*.yml in a directory (sorted), or a single file."""
    p = Path(path)
    files = sorted(p.glob("*.y*ml")) if p.is_dir() else [p]
    if not files:
        raise RulesetError(f"no YAML ruleset files found at {p}")

    hasher = hashlib.sha256()
    rules: list[dict] = []
    settings: dict = {}
    rule_overrides: dict = {}
    version = None
    sources = []
    seen_ids: set[str] = set()

    for f in files:
        raw = f.read_bytes()
        hasher.update(raw)
        data = yaml.safe_load(raw) or {}
        sources.append(str(f))
        if version is None:
            version = data.get("version")
        # Later files may extend settings (shallow merge, lists/dicts replaced).
        for k, v in (data.get("settings") or {}).items():
            if isinstance(v, dict) and isinstance(settings.get(k), dict):
                settings[k].update(v)
            else:
                settings[k] = v
        _merge_rule_overrides(rule_overrides, data, str(f))
        for idx, rule in enumerate(data.get("rules") or []):
            _validate_rule(rule, idx, str(f))
            if rule["id"] in seen_ids:
                raise RulesetError(f"{f}: duplicate rule id {rule['id']!r}")
            seen_ids.add(rule["id"])
            rules.append(rule)

    if version is None:
        raise RulesetError("ruleset missing top-level 'version'")
    _apply_rule_overrides(rules, rule_overrides)
    return Ruleset(
        version=int(version),
        settings=settings,
        rules=rules,
        content_hash=hasher.hexdigest(),
        sources=sources,
    )
