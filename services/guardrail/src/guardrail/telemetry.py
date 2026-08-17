"""Thin OTLP/HTTP-JSON exporter for GenAI spans (AIM-115 dogfood pilot).

This is the "thin SDK wrapper" path from docs/otel-genai-integration-guide.md
§2b, applied to our own first-party service. It is deliberately stdlib-only:
the receiver (services/ingest /v1/traces) speaks OTLP/HTTP *JSON* only, and
the official Python OTel SDK has no HTTP/JSON exporter (its HTTP exporter is
protobuf, which the receiver rejects with 415). So instead of pulling in the
SDK plus a custom exporter, we serialize the stable OTLP JSON mapping directly
— the whole contract is five allowlisted span attributes plus service.name.

Privacy: only the allowlisted gen_ai.* attributes and service.name are ever
put on the wire — never prompt/response text. This mirrors (and is enforced
again by) the receiver-side allowlist in services/ingest/src/otel.ts.

Configuration (all optional; unset endpoint = telemetry disabled, no-op):
  OTEL_EXPORTER_OTLP_ENDPOINT  base URL of the ingest service, e.g.
                               http://ingest:8080 ("/v1/traces" is appended)
  OTEL_EXPORTER_OTLP_HEADERS   "Authorization=Bearer <token>" (standard form)
  AIM_OTEL_SERVICE_NAME        service.name override (default: guardrail)
"""

from __future__ import annotations

import json
import os
import secrets
import time
import urllib.request
from contextlib import contextmanager
from typing import Iterator

DEFAULT_SERVICE_NAME = "guardrail"
# Flush automatically when the buffer reaches this many spans, so a long
# process never holds unbounded span state in memory.
AUTO_FLUSH_SPANS = 100

_endpoint: str | None = None
_auth_header: str | None = None
_service_name: str = DEFAULT_SERVICE_NAME
_spans: list[dict] = []


def configure(
    endpoint: str | None = None,
    auth_header: str | None = None,
    service_name: str | None = None,
    env: dict | None = None,
) -> None:
    """(Re)configure the exporter. Explicit args win over env; called with no
    args it reads the standard OTEL_* env vars. Unset endpoint disables export.
    """
    global _endpoint, _auth_header, _service_name
    env = env if env is not None else os.environ

    raw_endpoint = endpoint if endpoint is not None else env.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if raw_endpoint:
        base = raw_endpoint.rstrip("/")
        _endpoint = base if base.endswith("/v1/traces") else base + "/v1/traces"
    else:
        _endpoint = None

    if auth_header is not None:
        _auth_header = auth_header
    else:
        _auth_header = _parse_auth_header(env.get("OTEL_EXPORTER_OTLP_HEADERS"))

    _service_name = service_name or env.get("AIM_OTEL_SERVICE_NAME") or DEFAULT_SERVICE_NAME


def _parse_auth_header(raw: str | None) -> str | None:
    """Parse "Authorization=Bearer x[,k=v,...]" into a header value."""
    if not raw:
        return None
    for part in raw.split(","):
        key, _, value = part.partition("=")
        if key.strip().lower() == "authorization" and value.strip():
            return value.strip()
    return None


def enabled() -> bool:
    return _endpoint is not None


def _nano() -> int:
    return time.time_ns()


class _SpanRecorder:
    """Handle yielded by llm_span(); the call site records allowlisted facts."""

    def __init__(self) -> None:
        self.attributes: dict[str, object] = {}
        self.error = False

    def set_attribute(self, key: str, value: str | int) -> None:
        # Whitelist guard at the source: refuse anything outside the receiver
        # contract so a future edit can't accidentally ship content upstream.
        if key not in (
            "gen_ai.system",
            "gen_ai.request.model",
            "gen_ai.response.model",
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.output_tokens",
        ):
            raise ValueError(f"attribute {key!r} is not on the GenAI allowlist")
        self.attributes[key] = value

    def set_error(self) -> None:
        self.error = True


@contextmanager
def llm_span(system: str, request_model: str, name: str = "llm.chat") -> Iterator[_SpanRecorder]:
    """Time an LLM call and record a GenAI span. Exceptions mark the span
    errored and propagate — telemetry must never swallow the call site's error.
    """
    recorder = _SpanRecorder()
    recorder.set_attribute("gen_ai.system", system)
    recorder.set_attribute("gen_ai.request.model", request_model)
    start = _nano()
    trace_id = secrets.token_hex(16)
    span_id = secrets.token_hex(8)
    try:
        yield recorder
    except Exception:
        recorder.set_error()
        raise
    finally:
        _record_span(name, trace_id, span_id, start, _nano(), recorder)


def _attr_value(value: object) -> dict:
    if isinstance(value, bool):  # before int — bool is an int subclass
        return {"boolValue": value}
    if isinstance(value, int):
        # OTLP JSON encodes int64 as a string.
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def _record_span(name: str, trace_id: str, span_id: str, start_nano: int, end_nano: int, rec: _SpanRecorder) -> None:
    if not enabled():
        return
    _spans.append({
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "startTimeUnixNano": str(start_nano),
        "endTimeUnixNano": str(end_nano),
        "attributes": [{"key": k, "value": _attr_value(v)} for k, v in rec.attributes.items()],
        # OTLP StatusCode: 1 = Ok, 2 = Error. No message — the receiver drops it anyway.
        "status": {"code": 2 if rec.error else 1},
    })
    if len(_spans) >= AUTO_FLUSH_SPANS:
        flush()


def pending_spans() -> int:
    return len(_spans)


def flush(timeout: float = 10.0) -> int:
    """POST buffered spans as one ExportTraceServiceRequest. Returns the number
    of spans exported (0 when disabled or empty). Raises on transport failure —
    the caller decides whether telemetry loss is fatal (the poller/CLI log and
    continue; losing a call's LLM result is not acceptable, losing a span is).
    """
    if not enabled() or not _spans:
        return 0
    spans, _spans[:] = _spans[:], []
    body = json.dumps({
        "resourceSpans": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": _service_name}},
            ]},
            "scopeSpans": [{
                "scope": {"name": f"{_service_name}.llm"},
                "spans": spans,
            }],
        }],
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if _auth_header:
        headers["Authorization"] = _auth_header
    req = urllib.request.Request(_endpoint, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"OTLP export failed: HTTP {resp.status}")
    except Exception:
        # Put the spans back so a retry (or process shutdown flush) can resend;
        # the receiver dedupes on trace/span id, so re-export is safe.
        _spans[:0] = spans
        raise
    return len(spans)


def _reset_for_tests() -> None:
    global _endpoint, _auth_header, _service_name
    _endpoint = None
    _auth_header = None
    _service_name = DEFAULT_SERVICE_NAME
    _spans.clear()
