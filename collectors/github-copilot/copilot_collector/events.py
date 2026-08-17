"""Canonical event construction for GitHub Copilot.

Conforms to packages/schema/schema/v1/ai-usage-event.schema.json.

Identity (locked): tool='other' + tool_raw='github_copilot'. No first-class
enum — reversible if Security later wants a schema minor.

Content policy: no prompt, completion, chat text, file path, or
code. additionalProperties is false at ingest; this module also rejects
out-of-schema keys locally.

Do not invent token counts. GitHub does not persist them locally.
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

from .extract import SessionRecord

SCHEMA_VERSION = "1.10"
TOOL_NAME = "other"
TOOL_RAW = "github_copilot"
PROVIDER = "github"

_MODEL_PROVIDER_PREFIXES = (
    ("claude", "anthropic"),
    ("gpt", "openai"),
    ("o1", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
    ("gemini", "google"),
    ("grok", "xai"),
    ("copilot", "github"),
)

ACTION_CLASSES = ("fs_read", "fs_write", "shell", "network", "mcp_call", "other")
_TOOL_CALL_KEYS = {
    "tool_name",
    "mcp_server",
    "action_class",
    "count",
    "duration_ms",
    "call_id",
    "parent_call_id",
    "result_status",
    "seq",
}

_KIND_TOOL_NAME = {
    "chat": "copilot.chat",
    "inline": "copilot.inline",
    "agent": "copilot.agent",
}


def format_ts(epoch_s: int | float | None = None) -> str:
    dt = (
        datetime.fromtimestamp(epoch_s, tz=timezone.utc)
        if epoch_s is not None and epoch_s > 0
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


def daily_session_id(raw_session_id: str, epoch_s: int | float | None = None) -> str:
    dt = (
        datetime.fromtimestamp(epoch_s, tz=timezone.utc)
        if epoch_s is not None and epoch_s > 0
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


def make_flags(*, unapproved: bool = True) -> list[dict]:
    if not unapproved:
        return []
    return [
        {
            "detector": "policy:unapproved-tool",
            "category": "policy",
            "severity": "low",
        }
    ]


def _base_event(
    *,
    session_id: str,
    model: str | None,
    ts_epoch_s: float | None,
    tool_version: str | None,
) -> dict:
    ev: dict = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": format_ts(ts_epoch_s),
        "host_ref": host_ref(),
        "user_ref": None,
        "tool": TOOL_NAME,
        "tool_raw": TOOL_RAW,
        "model": (model[:128] if isinstance(model, str) and model.strip() else None),
        "provider": derive_provider(model),
        "session_id": session_id[:128],
        "match_flags": make_flags(unapproved=True),
        "source": "endpoint",
    }
    if tool_version:
        ev["tool_version"] = str(tool_version)[:64]
    return ev


def new_usage_event(
    *,
    session_id: str,
    model: str | None,
    ts_epoch_s: float | None = None,
    tool_version: str | None = None,
) -> dict:
    ev = _base_event(
        session_id=session_id,
        model=model,
        ts_epoch_s=ts_epoch_s,
        tool_version=tool_version,
    )
    ev["event_type"] = "usage"
    validate(ev)
    return ev


def new_tool_use_event(
    *,
    session_id: str,
    model: str | None,
    ts_epoch_s: float | None = None,
    tool_version: str | None = None,
    tool_calls: list[dict],
) -> dict:
    _check_tool_calls(tool_calls)
    ev = _base_event(
        session_id=session_id,
        model=model,
        ts_epoch_s=ts_epoch_s,
        tool_version=tool_version,
    )
    ev["event_type"] = "tool_use"
    ev["tool_calls"] = tool_calls
    validate(ev)
    return ev


def events_from_record(rec: SessionRecord) -> list[dict]:
    sid = daily_session_id(rec.raw_session_id, rec.ts_epoch_s)
    out = [
        new_usage_event(
            session_id=sid,
            model=rec.model,
            ts_epoch_s=rec.ts_epoch_s,
            tool_version=rec.tool_version,
        )
    ]
    if rec.kind != "inventory" and rec.request_count >= 1:
        tool_name = _KIND_TOOL_NAME.get(rec.kind, "copilot.chat")
        out.append(
            new_tool_use_event(
                session_id=sid,
                model=rec.model,
                ts_epoch_s=rec.ts_epoch_s,
                tool_version=rec.tool_version,
                tool_calls=[
                    {
                        "tool_name": tool_name,
                        "action_class": "other",
                        "count": int(rec.request_count),
                    }
                ],
            )
        )
    return out


def _check_tool_calls(tool_calls: list) -> None:
    if not isinstance(tool_calls, list) or not tool_calls:
        raise ValueError("tool_calls must be a non-empty list")
    for tc in tool_calls:
        if not isinstance(tc, dict):
            raise ValueError("tool_calls entries must be objects")
        extra = set(tc) - _TOOL_CALL_KEYS
        if extra:
            raise ValueError(f"tool_calls entry has out-of-schema keys: {sorted(extra)}")
        if not isinstance(tc.get("tool_name"), str) or not (1 <= len(tc["tool_name"]) <= 64):
            raise ValueError("tool_name must be a string of 1..64 chars")
        if tc.get("action_class") not in ACTION_CLASSES:
            raise ValueError(f"bad action_class: {tc.get('action_class')!r}")
        if not isinstance(tc.get("count"), int) or tc["count"] < 1:
            raise ValueError("count must be an int >= 1")


def validate(event: dict) -> None:
    required = (
        "schema_version",
        "event_id",
        "ts",
        "host_ref",
        "tool",
        "session_id",
        "source",
        "match_flags",
        "model",
    )
    missing = [k for k in required if k not in event]
    if missing:
        raise ValueError(f"event missing required fields: {missing}")
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
        "event_type",
        "tool_calls",
        "configured_mcp_servers",
        "duration_ms",
        "status",
    }
    extra = set(event) - allowed
    if extra:
        raise ValueError(f"out-of-schema fields (ingest would reject): {sorted(extra)}")
    if event["tool"] != TOOL_NAME:
        raise ValueError(f"tool must be {TOOL_NAME!r}")
    if event.get("tool_raw") != TOOL_RAW:
        raise ValueError(f"tool_raw must be {TOOL_RAW!r}")
    if not re.fullmatch(r"1\.[0-9]+", event["schema_version"]):
        raise ValueError("bad schema_version")
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})", event["ts"]
    ):
        raise ValueError("ts must be RFC 3339 second precision")
    href = event.get("host_ref")
    if href is not None and not re.fullmatch(r"[0-9a-f]{64}", str(href)):
        raise ValueError("host_ref must be 64 lowercase hex chars")
    if event.get("event_type") == "tool_use":
        _check_tool_calls(event.get("tool_calls") or [])
    # Never invent tokens.
    for k in ("tokens_in", "tokens_out", "cost_estimate_usd"):
        if k in event:
            raise ValueError(f"{k} must not be invented for Copilot endpoint events")
    json.dumps(event)
