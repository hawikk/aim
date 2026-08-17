"""Signed build identity for endpoint collectors (AIM-646).

Each collector reports a ``build`` block in the batch envelope so ingest can
verify the install is a genuine AI Monitoring release (not a forked binary
that still presents a stolen device token).

Runtime contract (stdlib-only collectors):

* At **release** time, CI embeds a pre-signed ``build_attestation.json`` next
  to this module (Ed25519 over a canonical message; see
  ``docs/security/collector-build-attestation.md``).
* At **runtime**, the collector only *loads and reports* that JSON — no
  private key, no crypto libraries.
* Source checkouts without a signed file still report an **unsigned** build
  identity (package/version/tool) so shadow mode can measure coverage; ingest
  reject happens only when ``INGEST_ATTESTATION_MODE=enforce``.

Env overrides (tests / emergency):

* ``AIM_BUILD_ATTESTATION_FILE`` — path to a JSON attestation
* ``AIM_BUILD_ATTESTATION_JSON`` — raw JSON string
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# Canonical message version — must match services/ingest/src/attestation.ts.
ATTEST_MESSAGE_VERSION = "AIM-BUILD-ATTEST-V1"

# Fields that form the signed payload (order is part of the contract).
_SIGNED_FIELDS = ("package", "version", "tool", "git_sha", "built_at")


def canonical_message(fields: dict[str, str]) -> bytes:
    """Deterministic bytes signed at release / verified at ingest."""
    lines = [ATTEST_MESSAGE_VERSION]
    for key in _SIGNED_FIELDS:
        val = fields.get(key) or "-"
        lines.append(f"{key}={val}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _load_json_file(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _normalize(data: dict[str, Any], *, tool: str, version: str, package: str) -> dict[str, str]:
    """Return a wire-safe build block. Only string fields; drop junk."""
    out: dict[str, str] = {
        "package": str(data.get("package") or package),
        "version": str(data.get("version") or version),
        "tool": str(data.get("tool") or tool),
    }
    for key in ("git_sha", "built_at", "key_id", "sig"):
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()
    return out


def load_build_attestation(
    *,
    tool: str,
    version: str,
    package: str = "aimonitoring-security",
    module_file: str | None = None,
) -> dict[str, str]:
    """Load signed attestation if present; otherwise unsigned fallback.

    ``module_file`` should be ``__file__`` of the calling package so the
    adjacent ``build_attestation.json`` (release embed) is found.
    """
    # 1. Explicit env overrides (tests, emergency re-pin).
    env_json = os.environ.get("AIM_BUILD_ATTESTATION_JSON")
    if env_json and env_json.strip():
        try:
            data = json.loads(env_json)
            if isinstance(data, dict):
                return _normalize(data, tool=tool, version=version, package=package)
        except ValueError:
            pass

    env_file = os.environ.get("AIM_BUILD_ATTESTATION_FILE")
    if env_file and env_file.strip():
        loaded = _load_json_file(Path(env_file.strip()))
        if loaded is not None:
            return _normalize(loaded, tool=tool, version=version, package=package)

    # 2. Package-adjacent release embed.
    if module_file:
        adjacent = Path(module_file).resolve().parent / "build_attestation.json"
        loaded = _load_json_file(adjacent)
        if loaded is not None:
            return _normalize(loaded, tool=tool, version=version, package=package)

    # 3. Unsigned source-checkout fallback (still reports identity).
    return {
        "package": package,
        "version": version,
        "tool": tool,
    }
