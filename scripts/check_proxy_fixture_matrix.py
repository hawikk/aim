#!/usr/bin/env python3
"""Multi-vendor proxy fixture matrix.

Keeps Squid + ≥3 enterprise proxy formats green on every PR so the
live-export flip stays a config change, not a rediscovery.

Checks (each fixture):
  * sample file exists under collectors/proxy/
  * format key is registered in proxy_ingest.PARSERS
  * pinned --format and --format auto produce identical events
  * ≥ min_events schema-shaped source=proxy events
  * required field map on intermediate parse records (ts, src_ip, host)
  * privacy: raw RFC1918 clients / sample identity strings never appear in emit

Policy:
  * require_squid + min_enterprise_formats (default 3)

Usage:
    python3 scripts/check_proxy_fixture_matrix.py              # human report
    python3 scripts/check_proxy_fixture_matrix.py --check      # CI (exit 1)
    python3 scripts/check_proxy_fixture_matrix.py --self-test  # prove rules fire
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROXY_DIR = ROOT / "collectors" / "proxy"
MATRIX_PATH = PROXY_DIR / "fixture-matrix.json"
SCHEMA_PATH = (
    ROOT / "packages" / "schema" / "schema" / "v1" / "ai-usage-event.schema.json"
)

# Intermediate fields every vendor parser must map before to_event.
REQUIRED_PARSE_FIELDS = ("ts", "src_ip", "host")

# Emitted event fields that must be present after map (source=proxy shape).
REQUIRED_EVENT_FIELDS = (
    "schema_version",
    "event_id",
    "ts",
    "host_ref",
    "tool",
    "provider",
    "source",
)

TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _load_proxy_ingest():
    """Import collectors/proxy/proxy_ingest.py without polluting package path."""
    path = PROXY_DIR / "proxy_ingest.py"
    spec = importlib.util.spec_from_file_location("proxy_ingest_matrix", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    # proxy_ingest expects to live as a free module; set __file__ for salt paths.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_matrix(path: Path = MATRIX_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("fixture-matrix root must be an object")
    if not isinstance(data.get("fixtures"), list):
        raise ValueError("fixture-matrix.fixtures must be a list")
    return data


def _load_schema() -> dict | None:
    if not SCHEMA_PATH.is_file():
        return None
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return None
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _run_ingest(
    pi: Any,
    sample: Path,
    fmt: str,
    salt_file: str,
) -> tuple[list[dict], str, int]:
    out, err = io.StringIO(), io.StringIO()
    argv = [
        "--collector",
        "proxy-fixture-matrix",
        "--format",
        fmt,
        "--input",
        str(sample),
        "--detections",
        str(PROXY_DIR / "endpoints.json"),
        "--subnets",
        str(PROXY_DIR / "subnets.json"),
        "--salt-file",
        salt_file,
        "--coverage",
    ]
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = pi.main(argv)
    except SystemExit as exc:
        # argparse uses SystemExit(2) on bad choices; surface as non-zero rc
        code = exc.code if isinstance(exc.code, int) else 2
        return [], err.getvalue() or str(exc), code
    events: list[dict] = []
    for line in out.getvalue().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            # coverage report lines on stderr; stdout should be pure JSONL
            continue
    return events, err.getvalue(), rc


def _first_parseable_line(sample: Path, parse_fn) -> str | None:
    """Return the first non-comment line the pinned parser accepts as a record."""
    for raw in sample.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        try:
            rec = parse_fn(raw)
        except Exception:  # noqa: BLE001 — treat parse exceptions as non-data
            continue
        if isinstance(rec, dict):
            return raw
    return None


def _sample_identity_needles(sample: Path) -> list[str]:
    """Best-effort synthetic identity strings that must never appear in emit."""
    needles: list[str] = []
    text = sample.read_text(encoding="utf-8", errors="replace")
    # UPN-ish and DOMAIN\\user patterns used in synthetic fixtures.
    needles.extend(re.findall(r"[A-Za-z0-9._%+-]+@corp\.example\b", text))
    needles.extend(re.findall(r"corp\\[A-Za-z0-9._-]+", text, flags=re.I))
    # Squid / bluecoat bare usernames that appear as tokens (avoid short noise).
    for m in re.findall(r"\b([a-z][a-z0-9]{2,15})\b", text):
        if m in {
            "tcp",
            "get",
            "connect",
            "http",
            "https",
            "post",
            "allow",
            "denied",
            "tunnel",
            "none",
            "text",
            "html",
            "json",
            "direct",
            "proxied",
            "unknown",
            "identity",
            "network",
            "networks",
            "adusers",
            "umbrella",
            "zscaler",
            "paloalto",
            "bluecoat",
            "fields",
            "date",
            "time",
        }:
            continue
        if m in {
            "jsmith",
            "agarcia",
            "bwong",
            "sam",
            "lee",
            "dev",
            "svc",
            "bot",
        } or m.endswith("smith") or m.endswith("garcia"):
            needles.append(m)
    # De-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for n in needles:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def check_matrix(matrix: dict[str, Any] | None = None) -> list[str]:
    """Return human-readable error strings; empty == green."""
    errors: list[str] = []
    matrix = matrix if matrix is not None else _load_matrix()
    policy = matrix.get("policy") or {}
    require_squid = bool(policy.get("require_squid", True))
    min_enterprise = int(policy.get("min_enterprise_formats", 3))
    default_min_events = int(policy.get("min_events_per_fixture", 1))

    try:
        pi = _load_proxy_ingest()
    except Exception as exc:  # noqa: BLE001 — surface load failures as check errors
        return [f"cannot import proxy_ingest: {exc}"]

    parsers = getattr(pi, "PARSERS", {}) or {}
    fixtures = matrix.get("fixtures") or []
    if not fixtures:
        return ["fixture-matrix.fixtures is empty"]

    seen_ids: set[str] = set()
    squid_count = 0
    enterprise_formats: set[str] = set()
    schema = _load_schema()
    jsonschema = None
    if schema is not None:
        import jsonschema as _js

        jsonschema = _js

    tmp_root = tempfile.mkdtemp(prefix="proxy-fixture-matrix-")
    try:
        for i, fx in enumerate(fixtures):
            if not isinstance(fx, dict):
                errors.append(f"fixtures[{i}] must be an object")
                continue
            fid = fx.get("id") or f"idx{i}"
            if fid in seen_ids:
                errors.append(f"duplicate fixture id: {fid}")
            seen_ids.add(fid)

            fmt = fx.get("format")
            sample_rel = fx.get("sample")
            tier = fx.get("tier")
            min_events = int(fx.get("min_events") or default_min_events)

            if not fmt or not isinstance(fmt, str):
                errors.append(f"{fid}: missing format")
                continue
            format_ok = True
            if fmt not in parsers:
                format_ok = False
                errors.append(
                    f"{fid}: format {fmt!r} not in proxy_ingest.PARSERS "
                    f"(have {sorted(k for k in parsers if k != 'auto')})"
                )
            if not sample_rel:
                errors.append(f"{fid}: missing sample path")
                continue
            sample = PROXY_DIR / sample_rel
            if not sample.is_file():
                errors.append(f"{fid}: sample missing: {sample_rel}")
                continue
            if tier == "squid":
                squid_count += 1
            elif tier == "enterprise":
                enterprise_formats.add(fmt)
            else:
                errors.append(f"{fid}: tier must be 'squid' or 'enterprise', got {tier!r}")

            # Unknown format keys cannot be replayed (argparse choices).
            if not format_ok:
                continue

            # --- intermediate field map on first parseable data line ---
            parse_fn = parsers.get(fmt)
            if parse_fn is not None:
                line = _first_parseable_line(sample, parse_fn)
                if line is None:
                    errors.append(
                        f"{fid}: sample has no lines parseable by format {fmt!r}"
                    )
                else:
                    rec = parse_fn(line)
                    if not isinstance(rec, dict):
                        errors.append(
                            f"{fid}: pinned parser returned {type(rec).__name__}, "
                            "expected dict on first data line"
                        )
                    else:
                        for field in REQUIRED_PARSE_FIELDS:
                            if not rec.get(field):
                                errors.append(
                                    f"{fid}: parse map missing required field {field!r}"
                                )

            # --- pipeline: auto == pinned, schema, min events, privacy ---
            salt = os.path.join(tmp_root, f"{fid}.salt")
            pinned, err_p, rc_p = _run_ingest(pi, sample, fmt, salt)
            auto, err_a, rc_a = _run_ingest(pi, sample, "auto", salt)
            if rc_p != 0:
                errors.append(f"{fid}: pinned ingest exit {rc_p}: {err_p.strip()[:200]}")
            if rc_a != 0:
                errors.append(f"{fid}: auto ingest exit {rc_a}: {err_a.strip()[:200]}")
            if pinned != auto:
                errors.append(
                    f"{fid}: auto events != pinned {fmt} events "
                    f"(auto={len(auto)} pinned={len(pinned)})"
                )
            if len(pinned) < min_events:
                errors.append(
                    f"{fid}: expected ≥{min_events} AI events, got {len(pinned)}"
                )

            blob = "\n".join(json.dumps(e, sort_keys=True) for e in pinned)
            for e_i, ev in enumerate(pinned):
                if not isinstance(ev, dict):
                    errors.append(f"{fid}: event[{e_i}] not an object")
                    continue
                if ev.get("source") != "proxy":
                    errors.append(
                        f"{fid}: event[{e_i}] source={ev.get('source')!r} != 'proxy'"
                    )
                for field in REQUIRED_EVENT_FIELDS:
                    if field not in ev:
                        errors.append(f"{fid}: event[{e_i}] missing {field}")
                ts = ev.get("ts")
                if isinstance(ts, str) and not TS_RE.match(ts):
                    errors.append(f"{fid}: event[{e_i}] bad ts {ts!r}")
                if jsonschema is not None and schema is not None:
                    try:
                        jsonschema.validate(ev, schema)
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"{fid}: event[{e_i}] schema: {exc}")

            # Privacy: no raw client IPs from common RFC1918 lab ranges in emit
            if re.search(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", blob):
                errors.append(f"{fid}: raw 10.x IP leaked into emitted events")
            for needle in _sample_identity_needles(sample):
                if needle and needle in blob:
                    errors.append(
                        f"{fid}: sample identity {needle!r} leaked into emit"
                    )

        if require_squid and squid_count < 1:
            errors.append("policy: require_squid but no fixture with tier=squid")
        if len(enterprise_formats) < min_enterprise:
            errors.append(
                f"policy: need ≥{min_enterprise} distinct enterprise formats, "
                f"got {len(enterprise_formats)} ({sorted(enterprise_formats)})"
            )
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    return errors


def report() -> int:
    matrix = _load_matrix()
    fixtures = matrix.get("fixtures") or []
    policy = matrix.get("policy") or {}
    print(
        f"proxy fixture matrix: {len(fixtures)} fixtures "
        f"(squid required={policy.get('require_squid')}, "
        f"min_enterprise={policy.get('min_enterprise_formats')})"
    )
    for fx in fixtures:
        print(
            f"  - {fx.get('id')}: format={fx.get('format')} "
            f"tier={fx.get('tier')} sample={fx.get('sample')}"
        )
    errs = check_matrix(matrix)
    if errs:
        print("FAIL:")
        for e in errs:
            print(f"  - {e}")
        return 1
    print(
        "OK: Squid + enterprise fixtures parse/map/emit cleanly "
        "(auto == pinned, schema + privacy)"
    )
    return 0


def self_test() -> int:
    """Prove the checker goes red on intentional fixture / policy breaks."""
    failures: list[str] = []

    # 1) Missing sample file
    matrix = _load_matrix()
    broken = deepcopy(matrix)
    if not broken["fixtures"]:
        print("self-test: matrix empty", file=sys.stderr)
        return 1
    broken["fixtures"][0]["sample"] = "samples/__does_not_exist__.log"
    errs = check_matrix(broken)
    if not any("sample missing" in e for e in errs):
        failures.append(f"missing-sample did not fire: {errs}")

    # 2) Corrupt a real sample copy so AI event count drops to 0
    real_sample = PROXY_DIR / matrix["fixtures"][0]["sample"]
    backup = real_sample.read_text(encoding="utf-8")
    try:
        real_sample.write_text(
            "# corrupted by check_proxy_fixture_matrix --self-test\n"
            "not a proxy log line at all\n",
            encoding="utf-8",
        )
        errs = check_matrix(matrix)
        if not any("AI events" in e or "parse map missing" in e for e in errs):
            failures.append(f"corrupt-sample did not fire: {errs}")
    finally:
        real_sample.write_text(backup, encoding="utf-8")

    # 3) Drop enterprise formats below policy floor
    thin = deepcopy(matrix)
    thin["fixtures"] = [
        fx for fx in thin["fixtures"] if fx.get("tier") == "squid"
    ][:1]
    thin["policy"] = dict(thin.get("policy") or {})
    thin["policy"]["min_enterprise_formats"] = 3
    errs = check_matrix(thin)
    if not any("enterprise formats" in e for e in errs):
        failures.append(f"min-enterprise policy did not fire: {errs}")

    # 4) Unknown format key
    bad_fmt = deepcopy(matrix)
    bad_fmt["fixtures"] = [deepcopy(matrix["fixtures"][0])]
    bad_fmt["fixtures"][0]["format"] = "not_a_real_format"
    bad_fmt["policy"] = {
        "require_squid": False,
        "min_enterprise_formats": 0,
        "min_events_per_fixture": 0,
    }
    # Keep tier squid so we only look for format registration error
    errs = check_matrix(bad_fmt)
    if not any("not in proxy_ingest.PARSERS" in e for e in errs):
        failures.append(f"unknown-format did not fire: {errs}")

    if failures:
        for f in failures:
            print(f"self-test FAIL: {f}", file=sys.stderr)
        return 1
    print(
        "self-test OK: checker fires on missing sample, corrupt fixture, "
        "enterprise floor, and unknown format"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="CI mode: exit 1 on fail")
    ap.add_argument(
        "--self-test", action="store_true", help="prove rules fire on intentional break"
    )
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    rc = report()
    if args.check:
        return rc
    # Human report still exits 0 unless --check (same convention as sibling guards)
    return 0


if __name__ == "__main__":
    sys.exit(main())
