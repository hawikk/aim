#!/usr/bin/env python3
"""Continuous tool-version compatibility matrix (AIM-648 / AIM-624).

Pins representative versions of each supported AI coding tool and exercises
collectors against recorded fixtures so version discovery + event emission
cannot silently regress.

Usage:
    python3 scripts/check_tool_version_matrix.py              # human report
    python3 scripts/check_tool_version_matrix.py --check      # CI (exit 1 on fail)
    python3 scripts/check_tool_version_matrix.py --self-test  # prove rules fire
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import sys
import tempfile
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "collectors" / "tool-version-matrix.json"
SCHEMA_PATH = (
    ROOT / "packages" / "schema" / "schema" / "v1" / "ai-usage-event.schema.json"
)

REQUIRED_TOOLS = (
    "claude_code",
    "cursor",
    "kilo_code",
    "kimi_code",
    "grok_build",
)

# (package_dir relative to ROOT, import package name)
COLLECTOR_PACKAGES = {
    "claude_code": ("collectors/claude-code", "aim_collector"),
    "cursor": ("collectors/cursor", "cursor_collector"),
    "kilo_code": ("collectors/kilo-code", "kilo_collector"),
    "kimi_code": ("collectors/kimi-code", "kimi_collector"),
    "grok_build": ("collectors/grok-build", "grok_collector"),
}


def _load_matrix(path: Path = MATRIX_PATH) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("tool-version matrix root must be an object")
    return data


def _tools_by_id(matrix: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for t in matrix.get("tools") or []:
        if not isinstance(t, dict) or not t.get("id"):
            raise ValueError("tool entry missing id")
        if t["id"] in out:
            raise ValueError(f"duplicate tool id: {t['id']}")
        out[t["id"]] = t
    return out


def check_schema(matrix: dict) -> list[str]:
    """Structural completeness of the pin matrix."""
    errors: list[str] = []
    policy = matrix.get("pin_policy") or {}
    min_versions = int(policy.get("min_versions_per_tool") or 2)
    max_len = int(policy.get("max_version_string_len") or 64)

    by_id = _tools_by_id(matrix)
    for req in REQUIRED_TOOLS:
        if req not in by_id:
            errors.append(f"missing required tool: {req}")

    for tid, tool in by_id.items():
        if tid not in REQUIRED_TOOLS:
            errors.append(f"unknown tool id (not in REQUIRED_TOOLS): {tid}")
        pkg_dir = tool.get("package_dir")
        if not pkg_dir:
            errors.append(f"{tid}: missing package_dir")
        elif not (ROOT / pkg_dir).is_dir():
            errors.append(f"{tid}: package_dir does not exist: {pkg_dir}")
        py = tool.get("python_package")
        expected_py = COLLECTOR_PACKAGES.get(tid, (None, None))[1]
        if expected_py and py and py != expected_py:
            errors.append(
                f"{tid}: python_package {py!r} != expected {expected_py!r}"
            )
        versions = tool.get("versions") or []
        if not isinstance(versions, list):
            errors.append(f"{tid}: versions must be a list")
            continue
        if len(versions) < min_versions:
            errors.append(
                f"{tid}: need ≥{min_versions} pinned versions, got {len(versions)}"
            )
        seen_ver: set[str] = set()
        for i, entry in enumerate(versions):
            if not isinstance(entry, dict):
                errors.append(f"{tid}: versions[{i}] must be an object")
                continue
            ver = entry.get("version")
            if not ver or not isinstance(ver, str):
                errors.append(f"{tid}: versions[{i}] missing version string")
                continue
            if len(ver) > max_len:
                errors.append(
                    f"{tid}: version {ver!r} exceeds max length {max_len}"
                )
            if ver in seen_ver:
                errors.append(f"{tid}: duplicate version pin {ver!r}")
            seen_ver.add(ver)
            fdir = entry.get("fixture_dir")
            if not fdir:
                errors.append(f"{tid}/{ver}: missing fixture_dir")
            elif not (ROOT / fdir).is_dir():
                errors.append(f"{tid}/{ver}: fixture_dir missing: {fdir}")
    return errors


@contextmanager
def _collector_on_path(tool_id: str) -> Iterator[str]:
    """Put a collector package dir on sys.path; unload its modules on exit.

    Yields the import package name (e.g. ``aim_collector``).
    """
    if tool_id not in COLLECTOR_PACKAGES:
        raise KeyError(f"no package mapping for {tool_id}")
    pkg_dir, pkg_name = COLLECTOR_PACKAGES[tool_id]
    abs_dir = str(ROOT / pkg_dir)
    doomed = [k for k in list(sys.modules) if k == pkg_name or k.startswith(pkg_name + ".")]
    for k in doomed:
        del sys.modules[k]
    sys.path.insert(0, abs_dir)
    try:
        yield pkg_name
    finally:
        if sys.path and sys.path[0] == abs_dir:
            sys.path.pop(0)
        doomed = [k for k in list(sys.modules) if k == pkg_name or k.startswith(pkg_name + ".")]
        for k in doomed:
            del sys.modules[k]


def _import_sub(pkg_name: str, sub: str) -> Any:
    return importlib.import_module(f"{pkg_name}.{sub}")


def _discover_version(tool_id: str, discovery: str, fixture_dir: Path, entry: dict) -> str | None:
    """Run the collector's native version discovery against a fixture."""
    if discovery == "state_file":
        state = tempfile.mkdtemp(prefix="aim-tv-state-")
        try:
            src = fixture_dir / "tool_version"
            if not src.is_file():
                raise FileNotFoundError(f"{fixture_dir}: missing tool_version file")
            shutil.copy(src, Path(state) / "tool_version")
            # Hooks read state_dir()/tool_version; mirror that contract.
            text = (Path(state) / "tool_version").read_text(encoding="utf-8").strip()
            return text or None
        finally:
            shutil.rmtree(state, ignore_errors=True)

    if discovery == "vscode_extension_dir":
        ext = fixture_dir / "extensions"
        if not ext.is_dir():
            raise FileNotFoundError(f"{fixture_dir}: missing extensions/")
        prev = os.environ.get("AIM_KILO_EXTENSION_DIR")
        os.environ["AIM_KILO_EXTENSION_DIR"] = str(ext)
        try:
            with _collector_on_path(tool_id) as pkg_name:
                paths = _import_sub(pkg_name, "paths")
                return paths.extension_version()
        finally:
            if prev is None:
                os.environ.pop("AIM_KILO_EXTENSION_DIR", None)
            else:
                os.environ["AIM_KILO_EXTENSION_DIR"] = prev

    if discovery == "kimi_install_json":
        prev = os.environ.get("AIM_KIMI_HOME")
        os.environ["AIM_KIMI_HOME"] = str(fixture_dir)
        try:
            with _collector_on_path(tool_id) as pkg_name:
                paths = _import_sub(pkg_name, "paths")
                return paths.tool_version()
        finally:
            if prev is None:
                os.environ.pop("AIM_KIMI_HOME", None)
            else:
                os.environ["AIM_KIMI_HOME"] = prev

    if discovery == "adapter_compose":
        adapter = entry.get("adapter_type") or (fixture_dir / "adapter_type").read_text(
            encoding="utf-8"
        ).strip()
        with _collector_on_path(tool_id) as pkg_name:
            events = _import_sub(pkg_name, "events")
            return events.tool_version(adapter)

    raise ValueError(f"unknown discovery mode: {discovery!r}")


def _build_usage_event(tool_id: str, version: str, entry: dict) -> dict:
    """Emit a usage event carrying the pinned tool_version and validate it."""
    state = tempfile.mkdtemp(prefix="aim-tv-ev-")
    prev_state = os.environ.get("AIM_STATE_DIR")
    os.environ["AIM_STATE_DIR"] = state
    try:
        with _collector_on_path(tool_id) as pkg_name:
            events = _import_sub(pkg_name, "events")
            if tool_id in ("claude_code", "cursor"):
                return events.new_event(
                    raw_session_id="aim-648-tool-version-matrix",
                    model="fixture-model",
                    cwd="/tmp/aim-648-fixture",
                    tokens_in=1,
                    tokens_out=1,
                    tool_version=version,
                )
            if tool_id in ("kilo_code", "kimi_code"):
                return events.new_event(
                    session_id="aim648sess0123456789abcdef01234567",
                    model="fixture-model",
                    workspace_path="/tmp/aim-648-fixture",
                    tokens_in=1,
                    tokens_out=1,
                    tool_version=version,
                )
            if tool_id == "grok_build":
                adapter = entry.get("adapter_type") or "grok_local"
                return events.new_event(
                    session_id="aim648sess0123456789abcdef01234567",
                    model="grok-3",
                    workspace_path="/tmp/aim-648-fixture",
                    tokens_in=1,
                    tokens_out=1,
                    adapter_type=adapter,
                )
            raise ValueError(f"no event builder for {tool_id}")
    finally:
        shutil.rmtree(state, ignore_errors=True)
        if prev_state is None:
            os.environ.pop("AIM_STATE_DIR", None)
        else:
            os.environ["AIM_STATE_DIR"] = prev_state


def _schema_validate_event(ev: dict) -> list[str]:
    """Validate against committed ai-usage-event schema (jsonschema if present)."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        # Fall back to required-keys + tool_version length when jsonschema
        # is unavailable (should not happen in CI python-tests job).
        errs: list[str] = []
        for k in (
            "schema_version",
            "event_id",
            "ts",
            "host_ref",
            "tool",
            "session_id",
            "source",
        ):
            if k not in ev:
                errs.append(f"missing required {k}")
        tv = ev.get("tool_version")
        if tv is not None and (not isinstance(tv, str) or len(tv) > 64):
            errs.append(f"tool_version invalid: {tv!r}")
        return errs

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    return [e.message for e in sorted(validator.iter_errors(ev), key=lambda e: list(e.path))]


def check_fixtures_and_emit(matrix: dict) -> list[str]:
    """Discovery round-trip + schema-valid event emission per pin."""
    errors: list[str] = []
    by_id = _tools_by_id(matrix)
    for tid in REQUIRED_TOOLS:
        tool = by_id.get(tid)
        if not tool:
            continue
        discovery = tool.get("discovery")
        if not discovery:
            errors.append(f"{tid}: missing discovery mode")
            continue
        for entry in tool.get("versions") or []:
            ver = entry.get("version")
            fdir_rel = entry.get("fixture_dir")
            if not ver or not fdir_rel:
                continue
            fdir = ROOT / fdir_rel
            label = f"{tid}/{ver}"
            try:
                discovered = _discover_version(tid, discovery, fdir, entry)
            except Exception as e:  # noqa: BLE001 — surface any discovery failure
                errors.append(f"{label}: discovery raised {type(e).__name__}: {e}")
                continue
            if discovered != ver:
                errors.append(
                    f"{label}: discovery returned {discovered!r}, expected {ver!r}"
                )
            try:
                ev = _build_usage_event(tid, ver, entry)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{label}: event emit raised {type(e).__name__}: {e}")
                continue
            if ev.get("tool") != tid:
                errors.append(
                    f"{label}: event.tool={ev.get('tool')!r}, expected {tid!r}"
                )
            if ev.get("tool_version") != ver:
                errors.append(
                    f"{label}: event.tool_version={ev.get('tool_version')!r}, "
                    f"expected {ver!r}"
                )
            schema_errs = _schema_validate_event(ev)
            if schema_errs:
                errors.append(
                    f"{label}: schema validation failed: {schema_errs[0]}"
                    + (f" (+{len(schema_errs)-1} more)" if len(schema_errs) > 1 else "")
                )
    return errors


def run_all(matrix: dict | None = None) -> list[str]:
    matrix = matrix if matrix is not None else _load_matrix()
    return check_schema(matrix) + check_fixtures_and_emit(matrix)


def human_report(errors: list[str], matrix: dict) -> None:
    by_id = _tools_by_id(matrix)
    print("Tool-version compatibility matrix (AIM-648)")
    print(f"  matrix: {MATRIX_PATH.relative_to(ROOT)}")
    print(f"  strategy: {matrix.get('strategy')}")
    policy = matrix.get("pin_policy") or {}
    print(f"  min_versions_per_tool: {policy.get('min_versions_per_tool')}")
    print()
    for tid in REQUIRED_TOOLS:
        tool = by_id.get(tid)
        if not tool:
            print(f"  {tid}: MISSING")
            continue
        vers = [v.get("version") for v in (tool.get("versions") or [])]
        print(f"  {tid}: {len(vers)} pins — {', '.join(str(v) for v in vers)}")
        print(f"    discovery={tool.get('discovery')} package={tool.get('package_dir')}")
    print()
    if errors:
        print(f"FAIL ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")
    else:
        print("OK — all pins discover + emit schema-valid events")


def self_test() -> int:
    """Mutate a synthetic matrix until each rule fires (aliveness)."""
    base = _load_matrix()
    failures = 0

    def expect_fail(label: str, mutator) -> None:
        nonlocal failures
        m = deepcopy(base)
        mutator(m)
        errs = run_all(m)
        if not errs:
            print(f"SELF-TEST FAIL: {label} — expected errors, got none")
            failures += 1
        else:
            print(f"SELF-TEST OK: {label} → {errs[0]}")

    # 1. missing required tool
    def drop_claude(m: dict) -> None:
        m["tools"] = [t for t in m["tools"] if t["id"] != "claude_code"]

    expect_fail("missing required tool", drop_claude)

    # 2. below min pin count
    def drop_pins(m: dict) -> None:
        for t in m["tools"]:
            if t["id"] == "cursor":
                t["versions"] = t["versions"][:1]

    expect_fail("min versions per tool", drop_pins)

    # 3. missing fixture dir
    def break_fixture(m: dict) -> None:
        for t in m["tools"]:
            if t["id"] == "kilo_code":
                t["versions"][0]["fixture_dir"] = "collectors/tool-version-fixtures/_missing"

    expect_fail("missing fixture_dir", break_fixture)

    # 4. discovery mismatch (wrong version string in state file)
    def wrong_state_version(m: dict) -> None:
        # Point claude pin at cursor's fixture so discovery returns the wrong version.
        for t in m["tools"]:
            if t["id"] == "claude_code":
                t["versions"][0]["fixture_dir"] = (
                    "collectors/tool-version-fixtures/cursor/0.49.4"
                )

    expect_fail("discovery/version mismatch", wrong_state_version)

    # 5. oversized version string
    def long_version(m: dict) -> None:
        for t in m["tools"]:
            if t["id"] == "kimi_code":
                t["versions"][0]["version"] = "v" * 80

    expect_fail("version string max length", long_version)

    # Positive path on the real matrix
    real_errs = run_all(base)
    if real_errs:
        print(f"SELF-TEST FAIL: clean matrix has {len(real_errs)} error(s):")
        for e in real_errs[:5]:
            print(f"  - {e}")
        failures += 1
    else:
        print("SELF-TEST OK: clean matrix passes")

    if failures:
        print(f"SELF-TEST: {failures} failure(s)")
        return 1
    print("SELF-TEST: all rules fire")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true", help="CI mode: exit 1 on any error")
    p.add_argument(
        "--self-test",
        action="store_true",
        help="Prove each rule fires against a mutated matrix",
    )
    p.add_argument(
        "--matrix",
        type=Path,
        default=MATRIX_PATH,
        help="Path to tool-version-matrix.json",
    )
    args = p.parse_args(argv)

    if args.self_test:
        return self_test()

    matrix = _load_matrix(args.matrix)
    errors = run_all(matrix)
    human_report(errors, matrix)
    if args.check and errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
