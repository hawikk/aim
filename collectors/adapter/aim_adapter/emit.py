"""Build metadata-only ai-usage-event records from adapter extraction rows."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .identity import IdentityContext, Pseudonymizer

SCHEMA_VERSION = "1.9"

# Content-ish keys a buggy surface might attach — never allowed on the wire.
DEFAULT_FORBIDDEN_KEYS = frozenset(
    {
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
        "arguments",
        "title",
        "page_title",
        "file_contents",
        "message",
        "messages",
        "input",
        "output",
    }
)

FIRST_CLASS_TOOLS = frozenset(
    {
        "claude_code",
        "cursor",
        "kilo_code",
        "kimi_code",
        "grok_build",
        "genai_app",
        "other",
    }
)


def strip_forbidden(obj: dict[str, Any], extra: list[str] | None = None) -> dict[str, Any]:
    ban = DEFAULT_FORBIDDEN_KEYS | {k.lower() for k in (extra or [])}
    return {k: v for k, v in obj.items() if k.lower() not in ban}


def format_ts(raw: str | int | float | None = None) -> str:
    """RFC 3339 UTC, second precision, Z or offset suffix (schema pattern)."""
    if isinstance(raw, (int, float)):
        # Heuristic: ms vs s
        epoch = raw / 1000.0 if raw > 10_000_000_000 else float(raw)
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(raw, str) and raw.strip():
        s = raw.strip()
        m = re.fullmatch(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})",
            s,
        )
        if m:
            return m.group(1) + m.group(3)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})", s):
            return s
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_flags(
    flag_names: list[str] | None = None,
    *,
    unapproved: bool = False,
) -> list[dict[str, Any]]:
    names = list(flag_names or [])
    if unapproved and "policy:unapproved-tool" not in names:
        names.append("policy:unapproved-tool")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    sev = {"secret": "high", "pii": "medium", "injection": "medium", "policy": "low"}
    for name in sorted(set(names)):
        if name in seen:
            continue
        seen.add(name)
        category = name.split(":", 1)[0] if ":" in name else "policy"
        out.append(
            {
                "detector": name[:64],
                "category": category if category in sev else "policy",
                "severity": sev.get(category, "low"),
            }
        )
    return out


def to_event(
    *,
    manifest: dict[str, Any],
    row: dict[str, Any],
    identity: IdentityContext,
    pseudo: Pseudonymizer,
    source: str,
    model_required: bool = False,
) -> dict[str, Any] | None:
    """Map one extraction row + manifest to a schema-shaped event, or None if empty."""
    extra_ban = list((manifest.get("privacy") or {}).get("forbidden_keys") or [])
    row = strip_forbidden(dict(row), extra_ban)

    schema_tool = manifest.get("schema_tool") or "other"
    if schema_tool not in FIRST_CLASS_TOOLS:
        schema_tool = "other"
    tool_id = manifest["id"]
    sanctioned = bool(manifest.get("sanctioned"))

    ts = format_ts(row.get("ts"))
    utc_date = ts[:10]
    raw_session = str(row.get("session_id") or row.get("session") or "anonymous")
    session_id = pseudo.daily_session_id(raw_session, utc_date)

    model = row.get("model")
    if model is not None:
        model = str(model)[:128] if str(model).strip() else None
    if model_required and source == "endpoint" and not model:
        # Endpoint usage events require model per schema constraints for some
        # sources; presence-only rows should not claim endpoint depth.
        model = row.get("model_fallback") or "unknown"

    provider = row.get("provider") or manifest.get("provider")
    if provider is not None:
        provider = str(provider)[:64]

    event: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": ts,
        "host_ref": pseudo.host_ref(identity.host_key),
        "user_ref": pseudo.user_ref(identity.user_key),
        "tool": schema_tool,
        "session_id": session_id[:128],
        "source": source,
        "match_flags": make_flags(row.get("match_flags"), unapproved=not sanctioned),
    }

    if schema_tool == "other":
        event["tool_raw"] = str(row.get("tool_raw") or tool_id)[:64]
    if row.get("tool_version"):
        event["tool_version"] = str(row["tool_version"])[:64]
    if model is not None:
        event["model"] = model
    elif source == "endpoint":
        # Schema allOf: source=endpoint requires the model key (null allowed when
        # the session log did not record one).
        event["model"] = None
    if provider is not None:
        event["provider"] = provider

    for tok_key in ("tokens_in", "tokens_out"):
        if tok_key in row and row[tok_key] is not None:
            try:
                event[tok_key] = max(0, int(row[tok_key]))
            except (TypeError, ValueError):
                pass

    if "cost_estimate_usd" in row and row["cost_estimate_usd"] is not None:
        try:
            event["cost_estimate_usd"] = max(0.0, float(row["cost_estimate_usd"]))
        except (TypeError, ValueError):
            pass

    repo = pseudo.repo_ref(row.get("repo_key") or identity.repo_key)
    if repo:
        event["repo_ref"] = repo

    # Network volume fields (proxy / os_egress presence)
    for k in ("bytes_up", "bytes_down", "http_status", "duration_ms"):
        if k in row and row[k] is not None:
            try:
                event[k] = int(row[k])
            except (TypeError, ValueError):
                pass
    if row.get("traffic_class") in ("application", "employee", "unknown"):
        event["traffic_class"] = row["traffic_class"]

    # Final forbidden-key guard on the event itself
    event = strip_forbidden(event, extra_ban)
    return event
