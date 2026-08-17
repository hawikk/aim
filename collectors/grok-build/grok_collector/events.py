"""Canonical event construction for Grok Build / Paperclip grok_local (AIM-271).

Conforms to packages/schema/schema/v1/ai-usage-event.schema.json (v1.8+).

Content policy (locked, AIM-16): no prompt text, conversation content, or
file contents on an event. Paperclip run metadata and adapter config carry
model/session identity only — never the prompt or tool payloads. Ingest
rejects out-of-schema fields whole.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import uuid
from datetime import datetime, timezone

SCHEMA_VERSION = "1.8"
TOOL_NAME = "grok_build"
PROVIDER = "xai"

# Paperclip adapter type → AIM tool enum. Only grok_local maps to this
# collector's tool name; other adapters have their own collectors.
_ADAPTER_TOOL = {
    "grok_local": "grok_build",
}

_MODEL_PROVIDER_PREFIXES = (
    ("grok", "xai"),
    ("claude", "anthropic"),
    ("gpt", "openai"),
    ("o1", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
    ("gemini", "google"),
    ("kimi", "kimi"),
    ("deepseek", "deepseek"),
)


def _now_iso() -> str:
    return format_ts(None)


def format_ts(epoch_s: int | float | None = None) -> str:
    """RFC 3339 UTC, second precision, Z suffix (schema ts pattern)."""
    dt = (
        datetime.fromtimestamp(epoch_s, tz=timezone.utc)
        if epoch_s is not None
        else datetime.now(timezone.utc)
    )
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def _salt() -> bytes:
    s = os.environ.get("AIM_HASH_SALT")
    if s:
        return s.encode()
    from . import config
    s = config.hash_salt()
    if s:
        return s.encode()
    from . import state
    f = state.state_dir() / "pseudo_salt"
    if not f.exists():
        f.write_text(uuid.uuid4().hex)
        os.chmod(f, 0o600)
    return f.read_text().strip().encode()


def _hmac64(value: str) -> str:
    return hmac.new(_salt(), value.encode(), hashlib.sha256).hexdigest()


def host_ref() -> str:
    return _hmac64(platform.node() or "unknown-host")


def repo_ref(workspace_path: str | None) -> str | None:
    if not workspace_path:
        return None
    norm = os.path.normpath(workspace_path).lower().replace("\\", "/")
    return _hmac64(norm)


def daily_session_id(raw_session_id: str, epoch_s: int | float | None = None) -> str:
    """Re-hash stable run/session ids per UTC day (schema session_id rule)."""
    dt = (
        datetime.fromtimestamp(epoch_s, tz=timezone.utc)
        if epoch_s is not None
        else datetime.now(timezone.utc)
    )
    return _hmac64(dt.strftime("%Y-%m-%d") + "|" + raw_session_id)


def derive_provider(model: str | None) -> str:
    if not model:
        return PROVIDER
    name = model.strip().lower().split("/")[-1]
    for prefix, provider in _MODEL_PROVIDER_PREFIXES:
        if name.startswith(prefix):
            return provider
    return PROVIDER


def tool_version(adapter_type: str | None = None) -> str:
    from . import __version__
    adapter = adapter_type or "grok_local"
    return f"paperclip-{adapter}/{__version__}"[:64]


def make_flags(flag_names: list[str] | None = None) -> list[dict]:
    out = []
    for name in sorted(set(flag_names or [])):
        category = name.split(":", 1)[0] if ":" in name else "policy"
        sev = {"secret": "high", "pii": "medium", "injection": "medium"}.get(category, "low")
        out.append({
            "detector": name[:64],
            "category": category if category in ("secret", "pii", "injection", "policy") else "policy",
            "severity": sev,
        })
    return out


def new_event(
    *,
    session_id: str,
    model: str,
    ts_epoch_s: int | float | None = None,
    workspace_path: str | None = None,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    cost_estimate_usd: float | None = None,
    provider: str | None = None,
    flags: list[str] | None = None,
    adapter_type: str | None = None,
    duration_ms: int | None = None,
    status: str | None = None,
) -> dict:
    """Build a usage event. model is required for source=endpoint."""
    ev: dict = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": format_ts(ts_epoch_s),
        "host_ref": host_ref(),
        "user_ref": None,
        "tool": TOOL_NAME,
        "tool_version": tool_version(adapter_type),
        "model": (model or "")[:128] or "unknown",
        "provider": provider or derive_provider(model),
        "session_id": session_id[:128],
        "repo_ref": repo_ref(workspace_path),
        "match_flags": make_flags(flags),
        "source": "endpoint",
    }
    if tokens_in is not None:
        ev["tokens_in"] = int(tokens_in)
    if tokens_out is not None:
        ev["tokens_out"] = int(tokens_out)
    if cost_estimate_usd is not None:
        ev["cost_estimate_usd"] = float(cost_estimate_usd)
    if duration_ms is not None:
        ev["duration_ms"] = int(duration_ms)
    if status in ("ok", "error"):
        ev["status"] = status
    validate(ev)
    return ev


def validate(event: dict) -> None:
    required = ("schema_version", "event_id", "ts", "host_ref", "tool",
                "session_id", "source", "match_flags", "model")
    missing = [k for k in required if k not in event]
    if missing:
        raise ValueError(f"event missing required fields: {missing}")
    allowed = {
        "schema_version", "event_id", "ts", "host_ref", "user_ref",
        "tool", "tool_raw", "tool_version", "model", "provider",
        "session_id", "tokens_in", "tokens_out", "cost_estimate_usd",
        "repo_ref", "match_flags", "source", "event_type", "tool_calls",
        "configured_mcp_servers", "duration_ms", "status",
    }
    extra = set(event) - allowed
    if extra:
        raise ValueError(f"out-of-schema fields (ingest would reject): {sorted(extra)}")
    if not re.fullmatch(r"1\.[0-9]+", event["schema_version"]):
        raise ValueError("bad schema_version")
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})", event["ts"]
    ):
        raise ValueError("ts must be RFC 3339 second precision")
    for k in ("host_ref", "repo_ref"):
        v = event.get(k)
        if v is not None and not re.fullmatch(r"[0-9a-f]{64}", str(v)):
            raise ValueError(f"{k} must be 64 lowercase hex chars")
    if event["tool"] != TOOL_NAME:
        raise ValueError(f"tool must be {TOOL_NAME!r}")
    if not event.get("model"):
        raise ValueError("endpoint events require model")
    json.dumps(event)
