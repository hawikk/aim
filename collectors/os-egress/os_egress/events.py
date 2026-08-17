"""Build metadata-only ai-usage-event records for OS egress."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .catalogue import Rule

SCHEMA_VERSION = "1.9"
SOURCE = "os_egress"
UNAPPROVED_DETECTOR = "policy:unapproved-tool"

# Schema first-class tool enum values (must stay in sync with packages/schema).
FIRST_CLASS_TOOLS = {
    "claude_code",
    "cursor",
    "kilo_code",
    "kimi_code",
    "grok_build",
    "genai_app",
}

# Content-ish keys a buggy adapter might attach — never allowed on the wire.
_FORBIDDEN_KEYS = {
    "url",
    "path",
    "query",
    "prompt",
    "prompt_text",
    "response",
    "response_text",
    "body",
    "content",
    "cmdline",
    "command_line",
    "args",
    "title",
    "page_title",
}


class Pseudonymizer:
    def __init__(self, salt: bytes | None = None):
        if salt is not None:
            self._salt = salt
            return
        env = os.environ.get("AIM_HASH_SALT")
        if env:
            self._salt = env.encode()
            return
        # Deterministic dev fallback — production must set AIM_HASH_SALT.
        self._salt = b"aim-os-egress-dev-salt-not-for-production"

    def hmac64(self, value: str) -> str:
        return hmac.new(self._salt, value.encode(), hashlib.sha256).hexdigest()


def _ts_second(raw: str | None) -> str:
    """RFC 3339 UTC at second precision (schema forbids fractional seconds)."""
    if raw:
        s = raw.strip()
        # 2026-07-29T12:00:00.123456Z → 2026-07-29T12:00:00Z
        m = re.fullmatch(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})",
            s,
        )
        if m:
            return m.group(1) + m.group(3)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})", s):
            return s
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _device_key(rec: dict[str, Any]) -> str:
    for k in ("device_id", "host_id", "hostname"):
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    env = os.environ.get("AIM_DEVICE_ID")
    if env and env.strip():
        return env.strip()
    return platform.node() or "unknown-host"


def _normalize_host(raw: str) -> str:
    h = raw.strip().lower()
    # Strip accidental URL wrappers a buggy adapter might pass.
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    h = h.split("?", 1)[0]
    h = h.split("#", 1)[0]
    if ":" in h and not h.startswith("["):
        # host:port
        host_part, _, port = h.rpartition(":")
        if port.isdigit():
            h = host_part
    return h.rstrip(".")


def parse_record(line_or_obj: str | dict[str, Any]) -> dict[str, Any] | None:
    """Normalize one JSONL line / dict into {ts, host, device_id, process_class}."""
    if isinstance(line_or_obj, str):
        line = line_or_obj.strip()
        if not line or line.startswith("#"):
            return None
        obj = json.loads(line)
    else:
        obj = dict(line_or_obj)

    # Hard strip forbidden content keys before anything else.
    for k in list(obj.keys()):
        if k.lower() in _FORBIDDEN_KEYS:
            obj.pop(k)

    host = obj.get("host") or obj.get("dest_host") or obj.get("hostname")
    if not host or not isinstance(host, str):
        return None
    host = _normalize_host(host)
    if not host or host in (".", "localhost", "127.0.0.1"):
        return None

    process_class = obj.get("process_class")
    if process_class not in (None, "browser", "desktop_app", "unknown"):
        process_class = "unknown"

    return {
        "ts": _ts_second(obj.get("ts") if isinstance(obj.get("ts"), str) else None),
        "host": host,
        "device_id": _device_key(obj),
        "process_class": process_class,
    }


def to_event(
    rec: dict[str, Any],
    rule: Rule,
    pseudo: Pseudonymizer,
    *,
    include_process_class: bool = False,
) -> dict[str, Any]:
    """Map a normalized record + catalogue rule to a schema-valid event."""
    seed = f"os_egress|{rec['ts']}|{rec['device_id']}|{rec['host']}|{rule.id}"
    event_id = str(uuid.UUID(bytes=hashlib.sha256(seed.encode()).digest()[:16], version=5))

    raw_tool = rule.tool or rule.provider
    if rule.tool in FIRST_CLASS_TOOLS:
        tool, tool_raw = rule.tool, None
    else:
        tool = "other"
        tool_raw = (raw_tool or "unknown")[:64]

    flags: list[dict[str, str]] = []
    if not rule.sanctioned:
        flags.append(
            {
                "detector": UNAPPROVED_DETECTOR,
                "category": "policy",
                "severity": "medium",
            }
        )

    host_ref = pseudo.hmac64(rec["device_id"])
    day = rec["ts"][:10]
    session_id = pseudo.hmac64(f"os_egress|{rec['device_id']}|{day}")[:32]

    ev: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "ts": rec["ts"],
        "host_ref": host_ref,
        "user_ref": None,
        "tool": tool,
        "model": None,
        "provider": (rule.provider or "unknown")[:64],
        "session_id": session_id,
        "match_flags": flags,
        "source": SOURCE,
        "traffic_class": "employee",
    }
    if tool_raw is not None:
        ev["tool_raw"] = tool_raw

    # process_class is intentionally NOT a schema field (v1.9). Kept local-only
    # unless a future schema minor adds it; include_process_class is reserved
    # for debug dumps and must not be set for production sinks.
    if include_process_class and rec.get("process_class"):
        # Debug only — would fail ingest; used by unit tests that assert strip.
        pass

    validate_local(ev)
    return ev


def validate_local(event: dict[str, Any]) -> None:
    """Hard local constraints mirroring the canonical schema."""
    required = (
        "schema_version",
        "event_id",
        "ts",
        "host_ref",
        "tool",
        "session_id",
        "source",
        "match_flags",
    )
    missing = [k for k in required if k not in event]
    if missing:
        raise ValueError(f"event missing required fields: {missing}")
    if event["source"] != SOURCE:
        raise ValueError("source must be os_egress")
    if not re.fullmatch(r"1\.[0-9]+", event["schema_version"]):
        raise ValueError("bad schema_version")
    if not re.fullmatch(r"[0-9a-f]{64}", event["host_ref"]):
        raise ValueError("host_ref must be 64 lowercase hex")
    if event["tool"] == "other" and not event.get("tool_raw"):
        raise ValueError("tool=other requires tool_raw")
    for k in _FORBIDDEN_KEYS:
        if k in event:
            raise ValueError(f"forbidden content field present: {k}")
    # additionalProperties discipline: only known keys
    allowed = {
        "schema_version",
        "event_id",
        "ts",
        "host_ref",
        "user_ref",
        "tool",
        "tool_raw",
        "tool_version",
        "model",
        "provider",
        "session_id",
        "tokens_in",
        "tokens_out",
        "cost_estimate_usd",
        "repo_ref",
        "match_flags",
        "source",
        "traffic_class",
        "bytes_up",
        "bytes_down",
        "duration_ms",
        "http_status",
    }
    extra = set(event) - allowed
    if extra:
        raise ValueError(f"out-of-schema fields: {sorted(extra)}")
