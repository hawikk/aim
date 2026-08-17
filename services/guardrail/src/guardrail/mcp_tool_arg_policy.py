"""MCP tool-argument policy: schema load, shape extraction, evaluation (AIM-664).

Policy can express allow / deny / confirm on (tool name + argument *shape*).
Shape is metadata-only:

  - top-level argument key names
  - JSON type class of each value (string|number|boolean|object|array|null)

Never argument *values*, never nested content, never command lines / paths as
strings. Endpoint code may pass a local ``tool_input`` dict into
:func:`shape_from_tool_input`; only the derived shape is used for matching.

This module is the pure evaluation core. Wiring into PreToolUse / guardrail
match rules is a follow-on; AIM-664 acceptance is schema + fixtures + unit tests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

EFFECTS = frozenset({"allow", "deny", "confirm"})
TYPE_CLASSES = frozenset(
    {"string", "number", "boolean", "object", "array", "null", "present"}
)

# Repo-relative default locations (resolved from this file → repo root).
_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parents[4]  # .../services/guardrail/src/guardrail → repo
DEFAULT_SCHEMA_PATH = (
    _REPO_ROOT / "policies" / "mcp" / "tool-argument-policy.schema.json"
)
DEFAULT_FIXTURES_DIR = _REPO_ROOT / "policies" / "mcp" / "fixtures"


class ToolArgPolicyError(ValueError):
    """Invalid policy document or evaluation input."""


@dataclass(frozen=True)
class Decision:
    """Result of evaluating one tool-call descriptor against a policy."""

    effect: str  # allow | deny | confirm
    rule_id: str | None  # None when default_effect applied
    priority: int | None
    matched: dict[str, Any]  # metadata-only evidence (no values)
    policy_id: str | None = None
    mode: str = "observe"

    def as_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect,
            "rule_id": self.rule_id,
            "priority": self.priority,
            "matched": self.matched,
            "policy_id": self.policy_id,
            "mode": self.mode,
        }


def type_class_of(value: Any) -> str:
    """Map a Python value to a JSON type class. Never returns the value."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, (list, tuple)):
        return "array"
    # Unknown host types (e.g. custom objects) collapse to "present".
    return "present"


def shape_from_tool_input(tool_input: Any) -> dict[str, Any]:
    """Derive metadata-only argument shape from a local tool_input mapping.

    Returns ``{"arg_keys": [...sorted...], "arg_key_types": {k: type_class}}``.
    Values are never copied into the result.
    """
    if not isinstance(tool_input, Mapping):
        return {"arg_keys": [], "arg_key_types": {}}
    types: dict[str, str] = {}
    for key, value in tool_input.items():
        if not isinstance(key, str) or not key:
            continue
        # Cap key length to the schema's max so adversarial huge keys don't
        # leak into evidence blobs.
        k = key if len(key) <= 64 else key[:64]
        types[k] = type_class_of(value)
    return {
        "arg_keys": sorted(types.keys()),
        "arg_key_types": dict(sorted(types.items())),
    }


def call_descriptor(
    *,
    mcp_server: str | None,
    tool_name: str | None,
    action_class: str | None = "mcp_call",
    tool_input: Any = None,
    arg_keys: Iterable[str] | None = None,
    arg_key_types: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build an evaluation input. Prefer ``tool_input`` (local) or explicit shape.

    When both are given, explicit ``arg_keys`` / ``arg_key_types`` win (already
    shaped telemetry path). Never accepts or stores argument values.
    """
    if arg_keys is not None or arg_key_types is not None:
        keys = sorted({str(k) for k in (arg_keys or []) if k})
        types = {
            str(k): str(v)
            for k, v in (arg_key_types or {}).items()
            if k and str(v) in TYPE_CLASSES
        }
        # Ensure keys from types appear even if arg_keys omitted.
        for k in types:
            if k not in keys:
                keys.append(k)
        keys = sorted(keys)
        shape = {"arg_keys": keys, "arg_key_types": {k: types.get(k, "present") for k in keys}}
    else:
        shape = shape_from_tool_input(tool_input)

    return {
        "mcp_server": mcp_server,
        "tool_name": tool_name,
        "action_class": action_class,
        **shape,
    }


@lru_cache(maxsize=4)
def _load_schema(path: str) -> Draft202012Validator:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(raw)
    return Draft202012Validator(raw)


def schema_validator(schema_path: Path | str | None = None) -> Draft202012Validator:
    path = Path(schema_path) if schema_path else DEFAULT_SCHEMA_PATH
    return _load_schema(str(path.resolve()))


def validate_policy(
    policy: Mapping[str, Any],
    *,
    schema_path: Path | str | None = None,
) -> None:
    """Raise :class:`ToolArgPolicyError` if ``policy`` fails the JSON Schema."""
    if not isinstance(policy, Mapping):
        raise ToolArgPolicyError("policy must be a mapping")
    validator = schema_validator(schema_path)
    errors = sorted(validator.iter_errors(policy), key=lambda e: list(e.path))
    if errors:
        msgs = []
        for err in errors[:8]:
            loc = ".".join(str(p) for p in err.absolute_path) or "<root>"
            msgs.append(f"{loc}: {err.message}")
        raise ToolArgPolicyError("policy schema validation failed: " + "; ".join(msgs))
    # Extra semantic checks the schema can't express cleanly.
    if policy.get("default_effect") not in EFFECTS:
        raise ToolArgPolicyError("default_effect must be allow|deny|confirm")
    for i, rule in enumerate(policy.get("rules") or []):
        if not isinstance(rule, Mapping):
            raise ToolArgPolicyError(f"rules[{i}] must be a mapping")
        if rule.get("effect") not in EFFECTS:
            raise ToolArgPolicyError(f"rules[{i}].effect must be allow|deny|confirm")
        shape = (rule.get("match") or {}).get("arg_shape") or {}
        kc = shape.get("key_count") or {}
        if "min" in kc and "max" in kc and kc["min"] > kc["max"]:
            raise ToolArgPolicyError(
                f"rules[{i}].match.arg_shape.key_count: min > max"
            )


def load_policy(
    path: Path | str,
    *,
    schema_path: Path | str | None = None,
) -> dict[str, Any]:
    """Load + validate a policy JSON file. Returns a plain dict."""
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolArgPolicyError(f"cannot load policy {p}: {exc}") from exc
    validate_policy(data, schema_path=schema_path)
    return data


def _match_name(matcher: Any, actual: str | None) -> bool:
    if matcher is None:
        return True
    if actual is None or actual == "":
        return False
    if matcher == "*":
        return True
    if isinstance(matcher, str):
        return actual == matcher
    if not isinstance(matcher, Mapping) or len(matcher) != 1:
        return False
    kind, needle = next(iter(matcher.items()))
    if not isinstance(needle, str):
        return False
    if kind == "equals":
        return actual == needle
    if kind == "prefix":
        return actual.startswith(needle)
    if kind == "suffix":
        return actual.endswith(needle)
    if kind == "contains":
        return needle in actual
    return False


def _match_arg_shape(shape_spec: Mapping[str, Any] | None, call: Mapping[str, Any]) -> bool:
    if not shape_spec:
        return True
    keys = list(call.get("arg_keys") or [])
    key_set = set(keys)
    types = call.get("arg_key_types") or {}

    if "keys_all" in shape_spec:
        needed = set(shape_spec["keys_all"] or [])
        if not needed.issubset(key_set):
            return False
    if "keys_any" in shape_spec:
        any_of = set(shape_spec["keys_any"] or [])
        if not any_of.intersection(key_set):
            return False
    if "keys_none" in shape_spec:
        banned = set(shape_spec["keys_none"] or [])
        if banned.intersection(key_set):
            return False
    if "key_count" in shape_spec and shape_spec["key_count"] is not None:
        n = len(keys)
        kc = shape_spec["key_count"] or {}
        if "min" in kc and n < int(kc["min"]):
            return False
        if "max" in kc and n > int(kc["max"]):
            return False
    if "key_types" in shape_spec and shape_spec["key_types"]:
        for k, expected in shape_spec["key_types"].items():
            if k not in key_set:
                return False
            if expected == "present":
                continue
            actual_t = types.get(k)
            if actual_t != expected:
                return False
    return True


def _rule_matches(rule: Mapping[str, Any], call: Mapping[str, Any]) -> bool:
    match = rule.get("match") or {}
    if not _match_name(match.get("mcp_server"), call.get("mcp_server")):
        return False
    if not _match_name(match.get("tool_name"), call.get("tool_name")):
        return False
    if "action_class" in match:
        if call.get("action_class") != match["action_class"]:
            return False
    if not _match_arg_shape(match.get("arg_shape"), call):
        return False
    return True


def evaluate(
    policy: Mapping[str, Any],
    call: Mapping[str, Any],
    *,
    schema_path: Path | str | None = None,
    validate: bool = True,
) -> Decision:
    """Evaluate ``call`` against ``policy``. Returns a :class:`Decision`.

    Matching rules are ranked by ``priority`` descending, then list order.
    The first winner's effect is returned. If none match, ``default_effect``.
    """
    if validate:
        validate_policy(policy, schema_path=schema_path)

    mode = policy.get("mode") or "observe"
    policy_id = policy.get("policy_id")
    rules = list(policy.get("rules") or [])

    # Stable sort: higher priority first; preserve original index for ties.
    ranked = sorted(
        enumerate(rules),
        key=lambda pair: (-int(pair[1].get("priority", 100)), pair[0]),
    )

    for _, rule in ranked:
        if not _rule_matches(rule, call):
            continue
        evidence = {
            "mcp_server": call.get("mcp_server"),
            "tool_name": call.get("tool_name"),
            "action_class": call.get("action_class"),
            "arg_keys": list(call.get("arg_keys") or []),
            # types only — never values
            "arg_key_types": dict(call.get("arg_key_types") or {}),
            "match": rule.get("match"),
        }
        return Decision(
            effect=str(rule["effect"]),
            rule_id=str(rule["id"]),
            priority=int(rule.get("priority", 100)),
            matched=evidence,
            policy_id=policy_id,
            mode=str(mode),
        )

    return Decision(
        effect=str(policy["default_effect"]),
        rule_id=None,
        priority=None,
        matched={
            "mcp_server": call.get("mcp_server"),
            "tool_name": call.get("tool_name"),
            "action_class": call.get("action_class"),
            "arg_keys": list(call.get("arg_keys") or []),
            "arg_key_types": dict(call.get("arg_key_types") or {}),
            "default": True,
        },
        policy_id=policy_id,
        mode=str(mode),
    )


def evaluate_tool_input(
    policy: Mapping[str, Any],
    *,
    mcp_server: str | None,
    tool_name: str | None,
    tool_input: Any = None,
    action_class: str | None = "mcp_call",
    **kwargs: Any,
) -> Decision:
    """Convenience: shape local tool_input, then evaluate."""
    call = call_descriptor(
        mcp_server=mcp_server,
        tool_name=tool_name,
        action_class=action_class,
        tool_input=tool_input,
    )
    return evaluate(policy, call, **kwargs)
