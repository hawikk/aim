# OTel GenAI integration guide — pilot app teams

**Audience:** a first-party app team integrating with the AI Monitoring OTLP receiver.
**Time:** ~½ day. Config-only if you already emit OpenTelemetry traces; a thin SDK wrapper otherwise.
**What we collect:** operational metadata of your app's LLM calls — provider, model, token counts, latency, error rate. **Never** prompt or response text: the receiver enforces an attribute allowlist and drops everything else before storage (see "Privacy boundary" below).

## 1. Endpoint

```
POST {INGEST_BASE_URL}/v1/traces
Authorization: Bearer <app-team token>     # issued by the platform team
Content-Type: application/json             # OTLP/HTTP JSON only — protobuf is rejected with 415
```

Get `{INGEST_BASE_URL}` and a token from the platform team (#ai-monitoring). One token per app; tokens are scoped to the `/v1/traces` path.

## 2a. You already emit OTel traces (config-only, ~15 min)

Point a second exporter (or your collector) at our endpoint:

```yaml
# OpenTelemetry Collector — add alongside your existing exporter
exporters:
  otlphttp/aim:
    endpoint: "{INGEST_BASE_URL}"   # note: no /v1/traces suffix needed for the collector,
    #                                   it appends /v1/traces itself
    headers:
      Authorization: "Bearer <app-team token>"

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp/aim]     # add to your existing exporters list
```

**Important:** the exporter protocol must be HTTP/JSON. For SDK-built-in exporters set:

```
OTEL_EXPORTER_OTLP_PROTOCOL=http/json
OTEL_EXPORTER_OTLP_ENDPOINT={INGEST_BASE_URL}
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer <app-team token>
```

(protobuf support on our side is a planned follow-up; today the receiver answers `415` for it.)

## 2b. You don't emit OTel yet (thin wrapper, ~½ day)

Use your language's OTel SDK and instrument only the LLM call site. You need exactly four span attributes plus the service name — that is the entire contract.

> **Python caveat (found during the dogfood pilot):** the Python OTel SDK's HTTP exporter (`opentelemetry-exporter-otlp-proto-http`) is protobuf-only — it ignores `OTEL_EXPORTER_OTLP_PROTOCOL=http/json` and the receiver will answer `415`. Python services should either export through a local OTel Collector (§2a, which translates to JSON) or use a thin stdlib OTLP/HTTP-JSON wrapper — see `services/guardrail/src/guardrail/telemetry.py` (~150 lines, dependency-free) for the reference implementation we run in production. The JS SDK is unaffected: `@opentelemetry/exporter-trace-otlp-http` speaks HTTP/JSON natively.

```python
# Python example — via a local OTel Collector (see §2a) translating to HTTP/JSON:
# point the SDK's protobuf exporter at the collector, and the collector at us.
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

provider = TracerProvider(resource=Resource.create({"service.name": "claims-service"}))
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(
    endpoint="http://localhost:4318/v1/traces",   # local collector, NOT our receiver
)))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("claims-service.llm")

def call_llm(prompt: str) -> str:
    with tracer.start_as_current_span("llm.chat") as span:
        span.set_attribute("gen_ai.system", "openai")
        span.set_attribute("gen_ai.request.model", MODEL)
        try:
            resp = openai_client.chat.completions.create(model=MODEL, messages=[...])
        except Exception:
            span.set_status(trace.Status(trace.StatusCode.ERROR))
            raise
        span.set_attribute("gen_ai.usage.input_tokens", resp.usage.prompt_tokens)
        span.set_attribute("gen_ai.usage.output_tokens", resp.usage.completion_tokens)
        return resp.choices[0].message.content
```

Do **not** set `gen_ai.prompt`, `gen_ai.completion`, or any attribute containing request/response content — the receiver drops them, but they should never leave your process in the first place.

## 3. Privacy boundary (what the receiver guarantees)

Enforced in `services/ingest/src/otel.ts`, tested in `services/ingest/test/otel.test.ts`:

- **Attribute allowlist.** Only these span attributes are read: `gen_ai.system`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`. Only `service.name` is read from resource attributes. **Everything else is dropped at the boundary — before validation, storage, or logging.** The count of dropped attributes is exported as `ingest_otel_attributes_dropped_total`.
- **No raw archival.** Unlike the collector-event path, OTLP request bodies are never written to the raw-batch object store, because they may contain non-allowlisted attributes.
- **Non-GenAI spans are ignored** (spans without `gen_ai.*` attributes are accepted and skipped — you can point your whole trace pipeline at us, only LLM spans are metered).
- **Span status message is never stored** — only `ok`/`error`.
- Events are stored as canonical schema v1.3 (`source='otel'`, `tool='genai_app'` for first-party apps): see `packages/schema/schema/v1/ai-usage-event.schema.json` and `FIELDS.md`.
- **Claude Code is not an app.** Anthropic's Claude Code exporter (`service.name=claude-code`, or `claude_code.*` metrics on `POST /v1/metrics`) is stored as `tool='claude_code'` and appears on Tools / Overview. It is excluded from the Apps view. See `docs/ops/vendor-admin-telemetry.md`.

## 4. Verifying your integration

1. Send one test LLM call through the instrumented path.
2. Ask the platform team (or check the dashboard): **Apps** view → your `service.name` should appear with request count, models, tokens, error rate, and latency within a minute.
3. Idempotent retry is safe: events are keyed by a deterministic id derived from trace/span id, so exporter retries never double-count.

## 5. What you get back

The per-app view (`GET /api/apps/llm`, dashboard "Apps" tab) shows your service's model inventory, token/cost metering, error rate, and avg/p95 latency. If you want an alert on error-rate spikes or a new model appearing, file a ticket with the platform team — the guardrail engine reads the same event store.
