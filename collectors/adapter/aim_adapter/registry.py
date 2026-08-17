"""Load and validate tool adapter manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None  # type: ignore

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST_DIR = PACKAGE_ROOT / "manifests"
DEFAULT_SCHEMA_PATH = PACKAGE_ROOT / "schema" / "tool-adapter.manifest.schema.json"

SURFACE_TYPES = frozenset(
    {
        "local_session_logs",
        "editor_extension_hooks",
        "proxy_domain",
        "provider_api",
    }
)


class ManifestError(Exception):
    """Hard failure: invalid or unknown-surface manifest."""


def _load_schema(path: Path | None = None) -> dict[str, Any]:
    p = path or DEFAULT_SCHEMA_PATH
    return json.loads(p.read_text(encoding="utf-8"))


def load_manifest(path: str | Path, *, schema: dict[str, Any] | None = None) -> dict[str, Any]:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ManifestError(f"{path}: root must be a mapping")
    sch = schema if schema is not None else _load_schema()
    if jsonschema is not None:
        try:
            jsonschema.validate(raw, sch)
        except jsonschema.ValidationError as e:
            raise ManifestError(f"{path}: {e.message}") from e
    # Surface-type hard fail even without jsonschema
    for surf in raw.get("surfaces") or []:
        st = surf.get("type")
        if st not in SURFACE_TYPES:
            raise ManifestError(
                f"{path}: unknown surface type {st!r} — only a genuinely new "
                f"surface type requires code (known: {sorted(SURFACE_TYPES)})"
            )
    if raw.get("implementation") == "legacy":
        legacy = raw.get("legacy") or {}
        if not legacy.get("package"):
            raise ManifestError(f"{path}: legacy implementation requires legacy.package")
    privacy = raw.get("privacy") or {}
    if privacy.get("metadata_only") is not True:
        raise ManifestError(f"{path}: privacy.metadata_only must be true")
    return raw


def load_all_manifests(
    directory: str | Path | None = None,
    *,
    schema_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    d = Path(directory) if directory else DEFAULT_MANIFEST_DIR
    schema = _load_schema(Path(schema_path) if schema_path else None)
    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    paths = sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml"))
    for path in paths:
        m = load_manifest(path, schema=schema)
        if m["id"] in seen_ids:
            raise ManifestError(f"duplicate manifest id {m['id']!r} at {path}")
        seen_ids.add(m["id"])
        m["_manifest_path"] = str(path)
        out.append(m)
    return out


def manifest_by_id(
    tool_id: str,
    directory: str | Path | None = None,
) -> dict[str, Any]:
    for m in load_all_manifests(directory):
        if m["id"] == tool_id:
            return m
    raise ManifestError(f"no manifest for tool id {tool_id!r}")
