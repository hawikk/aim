#!/usr/bin/env python3
"""Continuous no-content-egress CI assertions (AIM-650).

Proves the privacy invariant that collector → ingest payloads cannot carry
prompt/response body fields. Four layers, all run on every PR (via the
python-tests job, which already covers collectors + ingest + schema):

  1. Schema static checks
     - closed objects keep ``additionalProperties: false``
     - forbidden content property names are never declared

  2. Sample harness
     - every committed ``valid-*`` example is free of forbidden keys (deep)
     - injecting each forbidden key into a valid sample is rejected by schema
     - required invalid fixtures still reject
     - nested injection under tool_calls / match_flags / configured_mcp_servers
       is rejected

  3. Collector emit harness
     - adapter ``strip_forbidden`` / ``to_event`` drop content-bearing keys
       from a fixture row that deliberately carries them
     - the resulting wire event validates against the schema

  4. Ingest archive path (AIM-83 raw-batch object store)
     - Postgres is safe because the canonical schema runs before the insert.
       The object archive is a *second* store on the same request path, so
       these checks pin that it is written after validation, that only
       schema-valid events reach it verbatim, that rejected payloads are
       reduced to a fingerprint, and that the regression test stays in place.

Usage:
    python3 scripts/no_content_egress.py              # print report
    python3 scripts/no_content_egress.py --check      # CI gate (exit 1 on fail)
    python3 scripts/no_content_egress.py --self-test  # prove rules fire
    python3 scripts/no_content_egress.py --json-report out.json
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
import shutil
import sys
import tempfile
import types
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover — CI installs jsonschema via requirements-dev
    Draft202012Validator = None  # type: ignore

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = (
    REPO_ROOT / "packages" / "schema" / "schema" / "v1" / "ai-usage-event.schema.json"
)
EXAMPLES_DIR = REPO_ROOT / "packages" / "schema" / "examples"
ADAPTER_EMIT = REPO_ROOT / "collectors" / "adapter" / "aim_adapter" / "emit.py"
ADAPTER_IDENTITY = REPO_ROOT / "collectors" / "adapter" / "aim_adapter" / "identity.py"
GEMINI_FIXTURE = (
    REPO_ROOT
    / "collectors"
    / "adapter"
    / "tests"
    / "fixtures"
    / "gemini_cli"
    / "usage.jsonl"
)
INGEST_SERVER = REPO_ROOT / "services" / "ingest" / "src" / "server.ts"
INGEST_OBJECT_STORE = REPO_ROOT / "services" / "ingest" / "src" / "object-store.ts"
INGEST_ARCHIVE_TEST = REPO_ROOT / "services" / "ingest" / "test" / "archive.test.ts"
ARCHIVE_SOURCES: tuple[Path, ...] = (
    INGEST_SERVER,
    INGEST_OBJECT_STORE,
    INGEST_ARCHIVE_TEST,
)

# Field names that re-introduce content collection. Exact match (schema style).
# Kept in sync with collectors/adapter/aim_adapter/emit.py DEFAULT_FORBIDDEN_KEYS
# plus the broader AIM-16 content vocabulary auditors expect blocked.
FORBIDDEN_CONTENT_KEYS: frozenset[str] = frozenset(
    {
        "prompt",
        "prompt_text",
        "prompts",
        "response",
        "response_text",
        "responses",
        "completion",
        "completions",
        "content",
        "body",
        "message",
        "messages",
        "arguments",
        "args",
        "input",
        "inputs",
        "output",
        "outputs",
        "code",
        "code_snippet",
        "code_snippets",
        "file_content",
        "file_contents",
        "diff",
        "diffs",
        "text",
        "raw_prompt",
        "raw_response",
        "raw_text",
        "snippet",
        "snippets",
        "keystroke",
        "keystrokes",
        "screenshot",
        "screenshots",
        "screen_content",
        "cmdline",
        "command_line",
        "page_title",
        "title",  # page titles are content-adjacent; not on wire events
        "url",
        "path",
        "query",
    }
)

# Nested object paths that must remain closed. Paths use dotted form; `[]` = items.
CLOSED_OBJECT_PATHS: tuple[str, ...] = (
    "$",
    "$.tool_calls[]",
    "$.configured_mcp_servers[]",
    "$.match_flags[]",
    "$.enforcement",
    "$.enforcement_posture",
)

# Committed invalid fixtures that pin the content-rejection contract.
REQUIRED_INVALID_EXAMPLES: tuple[str, ...] = (
    "invalid-contains-prompt-text.json",
    "invalid-tool-call-arguments.json",
    "invalid-response-body.json",
    "invalid-message-content.json",
)

NESTED_INJECTION_SITES: tuple[str, ...] = (
    "root",
    "tool_calls[0]",
    "match_flags[0]",
    "configured_mcp_servers[0]",
)

CANARY_VALUE = "AIM650-CONTENT-CANARY-do-not-store"


@dataclass
class Check:
    id: str
    layer: str  # schema | samples | emit | self_test
    ok: bool
    detail: str


@dataclass
class Report:
    schema: str = "aim.no_content_egress/v1"
    ok: bool = False
    checks: list[Check] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "ok": self.ok,
            "passed": sum(1 for c in self.checks if c.ok),
            "failed": sum(1 for c in self.checks if not c.ok),
            "checks": [asdict(c) for c in self.checks],
        }


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _schema_node_at(schema: dict[str, Any], path: str) -> dict[str, Any] | None:
    if path == "$":
        return schema
    assert path.startswith("$.")
    parts = path[2:].split(".")
    node: Any = schema
    for part in parts:
        is_items = part.endswith("[]")
        key = part[:-2] if is_items else part
        if not isinstance(node, dict):
            return None
        props = node.get("properties") or {}
        if key not in props:
            return None
        node = props[key]
        if is_items:
            if not isinstance(node, dict) or "items" not in node:
                return None
            node = node["items"]
    return node if isinstance(node, dict) else None


def _iter_property_names(schema: dict[str, Any]) -> Iterable[tuple[str, str]]:
    def walk(node: Any, path: str) -> Iterable[tuple[str, str]]:
        if not isinstance(node, dict):
            return
        props = node.get("properties")
        if isinstance(props, dict):
            for name, child in props.items():
                yield path, name
                child_path = f"{path}.{name}" if path != "$" else f"$.{name}"
                yield from walk(child, child_path)
        items = node.get("items")
        if isinstance(items, dict):
            yield from walk(items, f"{path}[]")
        for combinator in ("oneOf", "anyOf", "allOf"):
            alts = node.get(combinator)
            if isinstance(alts, list):
                for i, alt in enumerate(alts):
                    yield from walk(alt, f"{path}/{combinator}[{i}]")

    yield from walk(schema, "$")


def _deep_forbidden_keys(obj: Any, path: str = "$") -> list[str]:
    """Return JSON-pointer-ish paths of any forbidden content key found."""
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{path}.{k}" if path != "$" else f"$.{k}"
            if k in FORBIDDEN_CONTENT_KEYS:
                found.append(child)
            found.extend(_deep_forbidden_keys(v, child))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            found.extend(_deep_forbidden_keys(item, f"{path}[{i}]"))
    return found


def _inject(sample: dict[str, Any], site: str, key: str, value: Any) -> dict[str, Any] | None:
    """Return a copy of sample with key=value injected at site, or None if site N/A."""
    out = copy.deepcopy(sample)
    if site == "root":
        out[key] = value
        return out
    if site == "tool_calls[0]":
        calls = out.get("tool_calls")
        if not isinstance(calls, list) or not calls:
            return None
        if not isinstance(calls[0], dict):
            return None
        calls[0][key] = value
        return out
    if site == "match_flags[0]":
        flags = out.get("match_flags")
        if not isinstance(flags, list) or not flags:
            out["match_flags"] = [{"detector": "policy:probe", "category": "policy"}]
            flags = out["match_flags"]
        if not isinstance(flags[0], dict):
            return None
        flags[0][key] = value
        return out
    if site == "configured_mcp_servers[0]":
        servers = out.get("configured_mcp_servers")
        if not isinstance(servers, list) or not servers:
            out["configured_mcp_servers"] = [{"name": "probe", "scope": "user"}]
            out.setdefault("event_type", "inventory")
            servers = out["configured_mcp_servers"]
        if not isinstance(servers[0], dict):
            return None
        servers[0][key] = value
        return out
    raise ValueError(f"unknown injection site: {site}")


def check_schema(root: Path = REPO_ROOT) -> list[Check]:
    checks: list[Check] = []
    schema_path = root / SCHEMA_PATH.relative_to(REPO_ROOT)
    if not schema_path.is_file():
        return [
            Check(
                "schema.present",
                "schema",
                False,
                f"missing event schema at {schema_path.relative_to(root)}",
            )
        ]

    schema = _load_json(schema_path)
    checks.append(
        Check(
            "schema.present",
            "schema",
            True,
            f"schema present ({schema_path.relative_to(root)})",
        )
    )

    desc = str(schema.get("description") or "")
    title = str(schema.get("title") or "")
    metadata_claimed = (
        "metadata-only" in desc.lower()
        or "metadata-only" in title.lower()
        or "metadata only" in desc.lower()
    )
    checks.append(
        Check(
            "schema.metadata_only_claim",
            "schema",
            metadata_claimed,
            (
                "schema title/description assert metadata-only"
                if metadata_claimed
                else "schema title/description lost the metadata-only claim"
            ),
        )
    )

    for path in CLOSED_OBJECT_PATHS:
        node = _schema_node_at(schema, path)
        if node is None:
            checks.append(
                Check(
                    f"schema.closed:{path}",
                    "schema",
                    False,
                    f"expected closed object at {path} is missing from schema",
                )
            )
            continue
        ap = node.get("additionalProperties")
        ok = ap is False
        checks.append(
            Check(
                f"schema.closed:{path}",
                "schema",
                ok,
                (
                    f"{path} has additionalProperties: false"
                    if ok
                    else f"{path} additionalProperties={ap!r} (must be false)"
                ),
            )
        )

    offenders = [
        (path, name)
        for path, name in _iter_property_names(schema)
        if name in FORBIDDEN_CONTENT_KEYS
    ]
    if offenders:
        detail = "; ".join(f"{p}.{n}" if p != "$" else n for p, n in offenders[:12])
        checks.append(
            Check(
                "schema.no_content_properties",
                "schema",
                False,
                f"forbidden content properties declared: {detail}",
            )
        )
    else:
        checks.append(
            Check(
                "schema.no_content_properties",
                "schema",
                True,
                f"no forbidden content properties among {len(FORBIDDEN_CONTENT_KEYS)} banned names",
            )
        )

    if Draft202012Validator is None:
        checks.append(
            Check(
                "schema.valid_jsonschema",
                "schema",
                False,
                "jsonschema not installed",
            )
        )
    else:
        try:
            Draft202012Validator.check_schema(schema)
            checks.append(
                Check(
                    "schema.valid_jsonschema",
                    "schema",
                    True,
                    "schema is a valid Draft 2020-12 document",
                )
            )
        except Exception as exc:  # noqa: BLE001 — surface any schema defect
            checks.append(
                Check(
                    "schema.valid_jsonschema",
                    "schema",
                    False,
                    f"schema is not a valid Draft 2020-12 document: {exc}",
                )
            )

    return checks


def check_samples(root: Path = REPO_ROOT) -> list[Check]:
    checks: list[Check] = []
    schema_path = root / SCHEMA_PATH.relative_to(REPO_ROOT)
    examples_dir = root / EXAMPLES_DIR.relative_to(REPO_ROOT)

    if not schema_path.is_file() or Draft202012Validator is None:
        checks.append(
            Check(
                "samples.prereq",
                "samples",
                False,
                "schema or jsonschema missing; sample harness cannot run",
            )
        )
        return checks

    schema = _load_json(schema_path)
    validator = Draft202012Validator(schema)

    valid_paths = sorted(examples_dir.glob("valid-*.json"))
    if not valid_paths:
        checks.append(
            Check(
                "samples.valid_present",
                "samples",
                False,
                f"no valid-* examples under {examples_dir.relative_to(root)}",
            )
        )
        return checks

    checks.append(
        Check(
            "samples.valid_present",
            "samples",
            True,
            f"{len(valid_paths)} valid sample(s) under examples/",
        )
    )

    dirty: list[str] = []
    for path in valid_paths:
        doc = _load_json(path)
        hits = _deep_forbidden_keys(doc)
        if hits:
            dirty.append(f"{path.name}: {', '.join(hits[:6])}")
    checks.append(
        Check(
            "samples.valid_clean",
            "samples",
            not dirty,
            (
                f"all {len(valid_paths)} valid samples free of forbidden keys"
                if not dirty
                else f"content keys in valid samples: {'; '.join(dirty[:4])}"
            ),
        )
    )

    invalid_valids = [
        path.name
        for path in valid_paths
        if list(validator.iter_errors(_load_json(path)))
    ]
    checks.append(
        Check(
            "samples.valid_validate",
            "samples",
            not invalid_valids,
            (
                f"all {len(valid_paths)} valid samples pass schema"
                if not invalid_valids
                else f"valid samples failing schema: {', '.join(invalid_valids[:6])}"
            ),
        )
    )

    missing = [n for n in REQUIRED_INVALID_EXAMPLES if not (examples_dir / n).is_file()]
    checks.append(
        Check(
            "samples.invalid_present",
            "samples",
            not missing,
            (
                f"required invalid fixtures present: {', '.join(REQUIRED_INVALID_EXAMPLES)}"
                if not missing
                else f"missing invalid fixtures: {', '.join(missing)}"
            ),
        )
    )
    if not missing:
        still_valid = [
            name
            for name in REQUIRED_INVALID_EXAMPLES
            if validator.is_valid(_load_json(examples_dir / name))
        ]
        checks.append(
            Check(
                "samples.invalid_reject",
                "samples",
                not still_valid,
                (
                    "content-bearing invalid fixtures are rejected by schema"
                    if not still_valid
                    else f"invalid fixtures unexpectedly valid: {', '.join(still_valid)}"
                ),
            )
        )

    base = _load_json(valid_paths[0])
    for path in valid_paths:
        doc = _load_json(path)
        if isinstance(doc.get("tool_calls"), list) and doc["tool_calls"]:
            base_tool = doc
            break
    else:
        base_tool = base

    injection_failures: list[str] = []
    injection_count = 0
    for site in NESTED_INJECTION_SITES:
        sample_base = base_tool if site.startswith("tool_calls") else base
        keys = (
            sorted(FORBIDDEN_CONTENT_KEYS)
            if site == "root"
            else sorted(
                {
                    "prompt",
                    "prompt_text",
                    "response",
                    "response_text",
                    "body",
                    "content",
                    "message",
                    "messages",
                    "arguments",
                    "args",
                    "input",
                    "output",
                    "file_contents",
                    "snippet",
                }
            )
        )
        for key in keys:
            mutated = _inject(sample_base, site, key, CANARY_VALUE)
            if mutated is None:
                continue
            injection_count += 1
            if validator.is_valid(mutated):
                injection_failures.append(f"{site}+{key}")

    checks.append(
        Check(
            "samples.injection_reject",
            "samples",
            not injection_failures,
            (
                f"schema rejected {injection_count} content injections across "
                f"{len(NESTED_INJECTION_SITES)} sites"
                if not injection_failures
                else f"schema ACCEPTED content injections: {', '.join(injection_failures[:8])}"
            ),
        )
    )

    return checks


def _import_adapter(root: Path):
    """Load aim_adapter.emit + identity without requiring package install."""
    id_path = root / ADAPTER_IDENTITY.relative_to(REPO_ROOT)
    emit_path = root / ADAPTER_EMIT.relative_to(REPO_ROOT)
    if not id_path.is_file() or not emit_path.is_file():
        return None, None

    pkg_name = "aim_adapter_nce"
    for key in list(sys.modules):
        if key == pkg_name or key.startswith(pkg_name + "."):
            del sys.modules[key]

    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = [str(emit_path.parent)]  # type: ignore[attr-defined]
    pkg.__package__ = pkg_name
    sys.modules[pkg_name] = pkg

    id_spec = importlib.util.spec_from_file_location(f"{pkg_name}.identity", id_path)
    assert id_spec and id_spec.loader
    identity_mod = importlib.util.module_from_spec(id_spec)
    identity_mod.__package__ = pkg_name
    sys.modules[f"{pkg_name}.identity"] = identity_mod
    id_spec.loader.exec_module(identity_mod)

    emit_spec = importlib.util.spec_from_file_location(f"{pkg_name}.emit", emit_path)
    assert emit_spec and emit_spec.loader
    emit_mod = importlib.util.module_from_spec(emit_spec)
    emit_mod.__package__ = pkg_name
    sys.modules[f"{pkg_name}.emit"] = emit_mod
    emit_spec.loader.exec_module(emit_mod)
    return emit_mod, identity_mod


def check_emit(root: Path = REPO_ROOT) -> list[Check]:
    checks: list[Check] = []
    schema_path = root / SCHEMA_PATH.relative_to(REPO_ROOT)
    fixture_path = root / GEMINI_FIXTURE.relative_to(REPO_ROOT)

    try:
        emit_mod, identity_mod = _import_adapter(root)
    except Exception as exc:  # noqa: BLE001
        checks.append(
            Check(
                "emit.adapter_load",
                "emit",
                False,
                f"failed to load adapter emit/identity: {exc}",
            )
        )
        return checks

    if emit_mod is None or identity_mod is None:
        checks.append(
            Check(
                "emit.adapter_load",
                "emit",
                False,
                "adapter emit/identity modules missing",
            )
        )
        return checks

    checks.append(
        Check("emit.adapter_load", "emit", True, "adapter emit + identity loadable")
    )

    dirty = {
        k: CANARY_VALUE
        for k in (
            "prompt",
            "prompt_text",
            "response",
            "response_text",
            "body",
            "content",
            "args",
            "arguments",
            "message",
            "messages",
            "input",
            "output",
            "file_contents",
            "cmdline",
            "url",
            "path",
            "query",
        )
    }
    dirty["model"] = "claude-sonnet-4-5"
    dirty["tokens_in"] = 12
    cleaned = emit_mod.strip_forbidden(dirty)
    residual = sorted(set(cleaned) & FORBIDDEN_CONTENT_KEYS)
    checks.append(
        Check(
            "emit.strip_forbidden",
            "emit",
            not residual,
            (
                f"strip_forbidden removed content keys; kept {sorted(cleaned.keys())}"
                if not residual
                else f"strip_forbidden left content keys: {residual}"
            ),
        )
    )

    if not fixture_path.is_file():
        checks.append(
            Check(
                "emit.fixture_present",
                "emit",
                False,
                f"missing adapter fixture {fixture_path.relative_to(root)}",
            )
        )
        return checks

    content_row = None
    for line in fixture_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if "prompt_text" in row or "response_text" in row:
            content_row = row
            break
    if content_row is None:
        content_row = {
            "timestamp": "2026-07-29T11:00:00Z",
            "session_id": "harness-sess",
            "model": "gemini-2.5-flash",
            "input_tokens": 10,
            "output_tokens": 4,
            "prompt_text": CANARY_VALUE,
            "response_text": CANARY_VALUE,
        }

    checks.append(
        Check(
            "emit.fixture_present",
            "emit",
            True,
            "content-bearing extraction row available for emit harness",
        )
    )

    row = {
        "ts": content_row.get("timestamp") or content_row.get("ts"),
        "session_id": content_row.get("session_id"),
        "model": content_row.get("model"),
        "tokens_in": content_row.get("input_tokens") or content_row.get("tokens_in"),
        "tokens_out": content_row.get("output_tokens") or content_row.get("tokens_out"),
        "prompt_text": content_row.get("prompt_text", CANARY_VALUE),
        "response_text": content_row.get("response_text", CANARY_VALUE),
        "body": CANARY_VALUE,
        "content": CANARY_VALUE,
        "arguments": CANARY_VALUE,
    }
    manifest = {
        "id": "gemini_cli",
        "schema_tool": "other",
        "sanctioned": False,
        "provider": "google",
        "privacy": {"metadata_only": True, "forbidden_keys": []},
    }
    identity = identity_mod.IdentityContext(
        host_key="aim-650-harness-host",
        user_key="aim-650-harness-user",
        repo_key=None,
    )
    pseudo = identity_mod.Pseudonymizer(salt="aim-650-harness-salt")
    event = emit_mod.to_event(
        manifest=manifest,
        row=row,
        identity=identity,
        pseudo=pseudo,
        source="endpoint",
        model_required=True,
    )
    if event is None:
        checks.append(
            Check(
                "emit.to_event",
                "emit",
                False,
                "to_event returned None for content-bearing row",
            )
        )
        return checks

    hits = _deep_forbidden_keys(event)
    canary_in_blob = CANARY_VALUE in json.dumps(event, sort_keys=True)
    checks.append(
        Check(
            "emit.wire_clean",
            "emit",
            not hits and not canary_in_blob,
            (
                "wire event free of forbidden keys and canary content"
                if not hits and not canary_in_blob
                else f"wire leak: keys={hits[:6]} canary={canary_in_blob}"
            ),
        )
    )

    if Draft202012Validator is None or not schema_path.is_file():
        checks.append(
            Check(
                "emit.schema_valid",
                "emit",
                False,
                "cannot validate wire event (schema/jsonschema missing)",
            )
        )
    else:
        validator = Draft202012Validator(_load_json(schema_path))
        errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
        ok = not errors
        checks.append(
            Check(
                "emit.schema_valid",
                "emit",
                ok,
                (
                    "wire event validates against ai-usage-event schema"
                    if ok
                    else f"wire event schema errors: {errors[0].message[:120]}"
                ),
            )
        )

    return checks


def _strip_ts_comments(src: str) -> str:
    """Drop // and /* */ comments so prose about a hazard is not read as one.

    Safe on the two ingest sources we scan: neither has a ``//`` inside a
    string literal (there is a check below that keeps it that way).
    """
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def _ts_block_after(src: str, anchor: str) -> str | None:
    """Return the brace-delimited block that opens after `anchor`."""
    start = src.find(anchor)
    if start < 0:
        return None
    open_at = src.find("{", start)
    if open_at < 0:
        return None
    depth = 0
    for i in range(open_at, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[open_at : i + 1]
    return None


def check_archive(root: Path = REPO_ROOT) -> list[Check]:
    """Layer 4: the ingest raw-batch object archive (AIM-83).

    Postgres cannot store content because the canonical schema runs before the
    insert and `rejected_events` keeps only a hash + key names. The object
    archive is a second store fed by the same request, so the metadata-only
    claim only holds end-to-end if the archive obeys the same two rules:
    validate first, and never write a payload the schema refused.
    """
    checks: list[Check] = []
    paths = {p: root / p.relative_to(REPO_ROOT) for p in ARCHIVE_SOURCES}
    missing = [p.relative_to(REPO_ROOT) for p, resolved in paths.items() if not resolved.is_file()]
    if missing:
        return [
            Check(
                "archive.sources_present",
                "archive",
                False,
                f"missing ingest archive sources: {', '.join(str(m) for m in missing)}",
            )
        ]
    checks.append(
        Check(
            "archive.sources_present",
            "archive",
            True,
            "ingest server / object-store / archive test present",
        )
    )

    server_raw = paths[INGEST_SERVER].read_text(encoding="utf-8")
    store_raw = paths[INGEST_OBJECT_STORE].read_text(encoding="utf-8")
    test_src = paths[INGEST_ARCHIVE_TEST].read_text(encoding="utf-8")
    server = _strip_ts_comments(server_raw)
    store = _strip_ts_comments(store_raw)

    # Comment stripping is only sound while no string literal carries "//".
    literal_slashes = re.search(r'"[^"\n]*//', server_raw) or re.search(r'"[^"\n]*//', store_raw)
    checks.append(
        Check(
            "archive.scannable",
            "archive",
            not literal_slashes,
            (
                "ingest archive sources contain no '//' string literals; comment "
                "stripping is sound"
                if not literal_slashes
                else "a '//' string literal appeared; the static checks below may misread it"
            ),
        )
    )

    # 1. Ordering. The schema is what rejects content-bearing fields, so the
    #    archive write must not happen until it has run.
    validate_at = server.find("validateEvent(")
    put_at = server.find("archive.put(")
    ordered = validate_at >= 0 and put_at >= 0 and validate_at < put_at
    checks.append(
        Check(
            "archive.validate_before_write",
            "archive",
            ordered,
            (
                "schema validation runs before the raw-batch archive write"
                if ordered
                else "archive.put() is reachable before validateEvent(): unvalidated "
                "events can land in object storage"
            ),
        )
    )

    # 2. What the archive write is handed. `body.events` is the unvalidated
    #    wire array and `body.collector` the unparsed envelope; neither may be
    #    passed into the archive call.
    block = _ts_block_after(server, "if (options.archive)")
    if block is None:
        checks.append(
            Check(
                "archive.validated_input_only",
                "archive",
                False,
                "could not locate the `if (options.archive)` block in server.ts",
            )
        )
    else:
        raw_inputs = sorted(
            name for name in ("body.events", "body.collector") if name in block
        )
        checks.append(
            Check(
                "archive.validated_input_only",
                "archive",
                not raw_inputs,
                (
                    "archive write consumes validated entries and the allowlisted "
                    "collector identity only"
                    if not raw_inputs
                    else f"archive write reads unvalidated wire input: {', '.join(raw_inputs)}"
                ),
            )
        )

    # 3. Rejected payloads are fingerprinted, never serialized. The type of the
    #    accepted branch is the other half: only a UsageEventV1 goes in verbatim.
    fingerprinted = "fingerprintPayload(record.payload)" in store
    typed_accepted = re.search(
        r'kind:\s*"accepted";\s*event:\s*UsageEventV1', store
    ) is not None
    checks.append(
        Check(
            "archive.rejects_fingerprinted",
            "archive",
            fingerprinted and typed_accepted,
            (
                "rejected payloads are reduced to hash + key names; only "
                "UsageEventV1 is archived verbatim"
                if fingerprinted and typed_accepted
                else f"archive serializer weakened (fingerprint={fingerprinted}, "
                f"typed_accepted={typed_accepted})"
            ),
        )
    )

    # 4. The behavioural regression test must stay. Static reads above cannot
    #    see runtime behaviour; this is the test that actually posts a
    #    content-bearing event and proves the bucket never sees it.
    has_canary = "CANARY" in test_src
    asserts_absent = "expect(body).not.toContain(CANARY)" in test_src
    checks.append(
        Check(
            "archive.regression_test",
            "archive",
            has_canary and asserts_absent,
            (
                "archive.test.ts still asserts a content canary never reaches the archive"
                if has_canary and asserts_absent
                else "archive.test.ts lost its content-canary assertion"
            ),
        )
    )

    return checks


def run_all(root: Path = REPO_ROOT) -> Report:
    report = Report()
    report.checks.extend(check_schema(root))
    report.checks.extend(check_samples(root))
    report.checks.extend(check_emit(root))
    report.checks.extend(check_archive(root))
    report.ok = all(c.ok for c in report.checks)
    return report


def _print_report(report: Report) -> None:
    print(f"no-content-egress ({report.schema})")
    by_layer: dict[str, list[Check]] = {}
    for c in report.checks:
        by_layer.setdefault(c.layer, []).append(c)
    for layer, checks in by_layer.items():
        print(f"\n== {layer}")
        for c in checks:
            mark = "ok  " if c.ok else "FAIL"
            print(f"  {mark} {c.id}: {c.detail}")
    print(
        f"\n{sum(1 for c in report.checks if c.ok)}/{len(report.checks)} passed"
        f" — {'PASS' if report.ok else 'FAIL'}"
    )


def self_test(root: Path = REPO_ROOT) -> int:
    """Mutate a temporary copy of the repo surface until each rule fires."""
    failures = 0

    def expect_fail(label: str, mutator) -> None:
        nonlocal failures
        with tempfile.TemporaryDirectory(prefix="aim650-") as tmp:
            tmp_root = Path(tmp)
            schema_src = root / SCHEMA_PATH.relative_to(REPO_ROOT)
            examples_src = root / EXAMPLES_DIR.relative_to(REPO_ROOT)
            adapter_src = root / "collectors" / "adapter"
            schema_dst = tmp_root / SCHEMA_PATH.relative_to(REPO_ROOT)
            examples_dst = tmp_root / EXAMPLES_DIR.relative_to(REPO_ROOT)
            adapter_dst = tmp_root / "collectors" / "adapter"
            schema_dst.parent.mkdir(parents=True, exist_ok=True)
            examples_dst.mkdir(parents=True, exist_ok=True)
            schema_dst.write_text(schema_src.read_text(encoding="utf-8"), encoding="utf-8")
            for p in examples_src.glob("*.json"):
                (examples_dst / p.name).write_text(
                    p.read_text(encoding="utf-8"), encoding="utf-8"
                )
            (adapter_dst / "aim_adapter").mkdir(parents=True, exist_ok=True)
            for name in ("emit.py", "identity.py", "__init__.py"):
                src = adapter_src / "aim_adapter" / name
                if src.is_file():
                    shutil.copy2(src, adapter_dst / "aim_adapter" / name)
            fix_src = adapter_src / "tests" / "fixtures" / "gemini_cli" / "usage.jsonl"
            fix_dst = (
                adapter_dst / "tests" / "fixtures" / "gemini_cli" / "usage.jsonl"
            )
            fix_dst.parent.mkdir(parents=True, exist_ok=True)
            if fix_src.is_file():
                shutil.copy2(fix_src, fix_dst)
            for rel in ARCHIVE_SOURCES:
                src = root / rel.relative_to(REPO_ROOT)
                dst = tmp_root / rel.relative_to(REPO_ROOT)
                dst.parent.mkdir(parents=True, exist_ok=True)
                if src.is_file():
                    shutil.copy2(src, dst)

            mutator(tmp_root)
            report = run_all(tmp_root)
            if report.ok:
                print(f"FAIL self-test {label}: expected at least one check to fail")
                failures += 1
            else:
                failed_ids = [c.id for c in report.checks if not c.ok]
                print(f"ok   self-test {label}: fired {failed_ids[:4]}")

    def open_root(tmp_root: Path) -> None:
        path = tmp_root / SCHEMA_PATH.relative_to(REPO_ROOT)
        schema = json.loads(path.read_text(encoding="utf-8"))
        schema["additionalProperties"] = True
        path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")

    def declare_prompt(tmp_root: Path) -> None:
        path = tmp_root / SCHEMA_PATH.relative_to(REPO_ROOT)
        schema = json.loads(path.read_text(encoding="utf-8"))
        schema.setdefault("properties", {})["prompt_text"] = {"type": "string"}
        path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")

    def dirty_valid(tmp_root: Path) -> None:
        path = tmp_root / EXAMPLES_DIR.relative_to(REPO_ROOT) / "valid-claude-code.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["prompt_text"] = CANARY_VALUE
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    def drop_invalid(tmp_root: Path) -> None:
        path = (
            tmp_root
            / EXAMPLES_DIR.relative_to(REPO_ROOT)
            / "invalid-contains-prompt-text.json"
        )
        path.unlink(missing_ok=True)

    def neuter_strip(tmp_root: Path) -> None:
        path = tmp_root / "collectors" / "adapter" / "aim_adapter" / "emit.py"
        text = path.read_text(encoding="utf-8")
        poisoned = text.replace(
            "return {k: v for k, v in obj.items() if k.lower() not in ban}",
            "return dict(obj)  # AIM-650 self-test poison",
        )
        if poisoned == text:
            poisoned = text.replace(
                "ban = DEFAULT_FORBIDDEN_KEYS | {k.lower() for k in (extra or [])}",
                "ban = set()  # AIM-650 self-test poison",
            )
        path.write_text(poisoned, encoding="utf-8")

    def _patch(tmp_root: Path, rel: Path, old: str, new: str, count: int = 1) -> None:
        path = tmp_root / rel.relative_to(REPO_ROOT)
        text = path.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"self-test anchor missing in {rel.name}: {old[:60]!r}")
        path.write_text(text.replace(old, new, count), encoding="utf-8")

    def archive_before_validation(tmp_root: Path) -> None:
        _patch(
            tmp_root,
            INGEST_SERVER,
            "    const valid: UsageEventV1[] = [];",
            "    if (options.archive) await options.archive.put('k', 'v');\n"
            "    const valid: UsageEventV1[] = [];",
        )

    def archive_raw_body(tmp_root: Path) -> None:
        _patch(tmp_root, INGEST_SERVER, "            archiveEntries,", "            body.events,")

    def archive_raw_collector(tmp_root: Path) -> None:
        _patch(
            tmp_root,
            INGEST_SERVER,
            "collector: hasIdentity(collectorIdentity) ? collectorIdentity : null,",
            "collector: body.collector ?? null,",
        )

    def archive_raw_reject(tmp_root: Path) -> None:
        _patch(
            tmp_root,
            INGEST_OBJECT_STORE,
            "      ...fingerprintPayload(record.payload),",
            "      payload: record.payload,",
        )

    def drop_archive_canary(tmp_root: Path) -> None:
        _patch(
            tmp_root,
            INGEST_ARCHIVE_TEST,
            "expect(body).not.toContain(CANARY);",
            "/* removed */",
            count=-1,
        )

    expect_fail("open_root_additionalProperties", open_root)
    expect_fail("declare_prompt_text_property", declare_prompt)
    expect_fail("dirty_valid_sample", dirty_valid)
    expect_fail("drop_invalid_prompt_fixture", drop_invalid)
    expect_fail("neuter_strip_forbidden", neuter_strip)
    expect_fail("archive_before_validation", archive_before_validation)
    expect_fail("archive_raw_body", archive_raw_body)
    expect_fail("archive_raw_collector", archive_raw_collector)
    expect_fail("archive_raw_reject", archive_raw_reject)
    expect_fail("drop_archive_canary", drop_archive_canary)

    print(f"\nself-test: {failures} failure(s)")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="CI gate: exit 1 when any assertion fails",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove each rule fires when its control is removed",
    )
    parser.add_argument(
        "--json-report",
        type=Path,
        default=None,
        help="write machine-readable report to this path",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    report = run_all()
    _print_report(report)
    if args.json_report is not None:
        args.json_report.write_text(
            json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.json_report}")

    if args.check and not report.ok:
        return 1
    return 0 if report.ok or not args.check else 1


if __name__ == "__main__":
    sys.exit(main())
