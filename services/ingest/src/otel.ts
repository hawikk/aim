import { createHash, createHmac } from "node:crypto";
import type { UsageEventV1 } from "./schema";

/**
 * OTLP/HTTP (JSON) receiver for OpenTelemetry GenAI semantic-convention spans
 * (AIM-105, approved AIM-101 proposal phase 2).
 *
 * PRIVACY-CRITICAL: the attribute allowlist below is the enforcement point
 * for "no prompt/response text can ever land in our store". Only allowlisted
 * span attributes are read out of a span; everything else is dropped at the
 * boundary — before validation, before storage, before logging. The OTLP
 * request body is never archived raw (unlike /v1/events batches) precisely
 * because it may carry non-allowlisted attributes.
 *
 * Supported conventions (stable HTTP JSON mapping of OTLP):
 *   resource.attributes["service.name"]         -> service_name (required)
 *   span attributes:
 *     gen_ai.system                             -> provider
 *     gen_ai.request.model / gen_ai.response.model -> model
 *     gen_ai.usage.input_tokens                 -> tokens_in
 *     gen_ai.usage.output_tokens                -> tokens_out
 *   span start/endTimeUnixNano                  -> ts (end, second precision), duration_ms
 *   span status.code                            -> status (ok | error; message dropped)
 */

const SPAN_ATTRIBUTE_ALLOWLIST = new Set([
  "gen_ai.system",
  "gen_ai.request.model",
  "gen_ai.response.model",
  "gen_ai.usage.input_tokens",
  "gen_ai.usage.output_tokens",
]);

const RESOURCE_ATTRIBUTE_ALLOWLIST = new Set(["service.name"]);

/** Max spans per OTLP request; larger exports must be split by the sender. */
export const MAX_OTLP_SPANS = 5000;

export interface OtlpMapStats {
  spansReceived: number;
  /** Spans that became canonical events. */
  spansMapped: number;
  /** Non-GenAI spans (no gen_ai.* attributes) — accepted but not metered. */
  spansSkippedNonGenai: number;
  /** GenAI spans we could not map (missing service.name / ids / timestamps). */
  spansRejected: number;
  /** Attributes dropped by the allowlist — the privacy audit signal. */
  attributesDropped: number;
}

export interface OtlpMapResult {
  events: UsageEventV1[];
  stats: OtlpMapStats;
  /** Per-rejection reason text (paths/field names only, never values). */
  errors: string[];
}

interface OtlpAnyValue {
  stringValue?: unknown;
  intValue?: unknown;
  doubleValue?: unknown;
  boolValue?: unknown;
}

interface OtlpKeyValue {
  key?: unknown;
  value?: OtlpAnyValue;
}

interface OtlpSpan {
  traceId?: unknown;
  spanId?: unknown;
  name?: unknown;
  startTimeUnixNano?: unknown;
  endTimeUnixNano?: unknown;
  attributes?: unknown;
  status?: { code?: unknown };
}

/** Read ONLY allowlisted attributes out of an OTLP attribute list. */
function extractAttributes(
  raw: unknown,
  allowlist: Set<string>,
  stats: { attributesDropped: number },
): Map<string, unknown> {
  const out = new Map<string, unknown>();
  if (!Array.isArray(raw)) return out;
  for (const entry of raw as OtlpKeyValue[]) {
    if (!entry || typeof entry.key !== "string") continue;
    if (!allowlist.has(entry.key)) {
      stats.attributesDropped += 1;
      continue;
    }
    const v = entry.value;
    if (!v || typeof v !== "object") continue;
    if (typeof v.stringValue === "string") out.set(entry.key, v.stringValue);
    else if (typeof v.intValue === "number") out.set(entry.key, v.intValue);
    // OTLP JSON encodes int64 as a string.
    else if (typeof v.intValue === "string" && /^-?\d+$/.test(v.intValue))
      out.set(entry.key, Number.parseInt(v.intValue, 10));
    else if (typeof v.doubleValue === "number") out.set(entry.key, v.doubleValue);
    else if (typeof v.boolValue === "boolean") out.set(entry.key, v.boolValue);
  }
  return out;
}

function unixNanoToMs(raw: unknown): number | null {
  if (typeof raw === "number" && Number.isFinite(raw)) return raw / 1e6;
  // OTLP JSON encodes uint64 as a string.
  if (typeof raw === "string" && /^\d+$/.test(raw)) return Number(raw) / 1e6;
  return null;
}

/** RFC 3339 with SECOND precision — the canonical schema forbids fractions. */
function toSecondPrecisionIso(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().slice(0, 19) + "Z";
}

/** Deterministic event id from trace/span id so exporter retries dedupe. */
function spanEventId(traceId: string, spanId: string): string {
  const hex = createHash("sha256").update(`aimon-otel:${traceId}:${spanId}`).digest("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function isErrorStatus(code: unknown): boolean {
  // OTLP JSON: StatusCode is 0/1/2 or the enum name.
  return code === 2 || code === "STATUS_CODE_ERROR";
}

/** Claude Code's OTel exporter uses service.name "claude-code" (or claude_code). */
export function isClaudeCodeServiceName(name: unknown): boolean {
  return typeof name === "string" && /^claude[-_]?code$/i.test(name.trim());
}

/**
 * Map an OTLP ExportTraceServiceRequest (JSON) into canonical usage events.
 * Non-GenAI spans are skipped silently; unmapped GenAI spans are counted and
 * reported. Pure function — no I/O, no logging, so nothing unfiltered can
 * leak through this layer.
 */
export function mapOtlpTraceRequest(body: unknown, hostSalt: string): OtlpMapResult {
  const stats: OtlpMapStats = {
    spansReceived: 0,
    spansMapped: 0,
    spansSkippedNonGenai: 0,
    spansRejected: 0,
    attributesDropped: 0,
  };
  const events: UsageEventV1[] = [];
  const errors: string[] = [];

  const resourceSpans =
    body !== null && typeof body === "object"
      ? (body as { resourceSpans?: unknown }).resourceSpans
      : undefined;
  if (!Array.isArray(resourceSpans)) {
    return { events, stats, errors: ["body must be an OTLP ExportTraceServiceRequest with resourceSpans[]"] };
  }

  for (const rs of resourceSpans) {
    if (!rs || typeof rs !== "object") continue;
    const resourceAttrs = extractAttributes(
      (rs as { resource?: { attributes?: unknown } }).resource?.attributes,
      RESOURCE_ATTRIBUTE_ALLOWLIST,
      stats,
    );
    const serviceName = resourceAttrs.get("service.name");

    const scopeSpans = (rs as { scopeSpans?: unknown }).scopeSpans;
    if (!Array.isArray(scopeSpans)) continue;

    for (const ss of scopeSpans) {
      const spans = (ss as { spans?: unknown } | null)?.spans;
      if (!Array.isArray(spans)) continue;

      for (const rawSpan of spans as OtlpSpan[]) {
        stats.spansReceived += 1;
        if (stats.spansReceived > MAX_OTLP_SPANS) {
          // Caller turns this into a 413 before we get here; belt-and-braces.
          errors.push(`span count exceeds ${MAX_OTLP_SPANS}`);
          return { events, stats, errors };
        }
        if (!rawSpan || typeof rawSpan !== "object") {
          stats.spansRejected += 1;
          continue;
        }

        const spanAttrs = extractAttributes(rawSpan.attributes, SPAN_ATTRIBUTE_ALLOWLIST, stats);
        const isGenAi = [...spanAttrs.keys()].some((k) => k.startsWith("gen_ai."));
        if (!isGenAi) {
          stats.spansSkippedNonGenai += 1;
          continue;
        }

        const reject = (reason: string) => {
          stats.spansRejected += 1;
          if (errors.length < 25) errors.push(reason);
        };

        if (typeof serviceName !== "string" || serviceName.length === 0) {
          reject("resource missing service.name (required for per-app attribution)");
          continue;
        }
        if (typeof rawSpan.traceId !== "string" || typeof rawSpan.spanId !== "string") {
          reject("span missing traceId/spanId");
          continue;
        }
        const endMs = unixNanoToMs(rawSpan.endTimeUnixNano);
        const startMs = unixNanoToMs(rawSpan.startTimeUnixNano);
        if (endMs === null) {
          reject("span missing endTimeUnixNano");
          continue;
        }

        const model =
          (spanAttrs.get("gen_ai.request.model") as string | undefined) ??
          (spanAttrs.get("gen_ai.response.model") as string | undefined);
        const tokensIn = spanAttrs.get("gen_ai.usage.input_tokens");
        const tokensOut = spanAttrs.get("gen_ai.usage.output_tokens");

        const claudeCode = isClaudeCodeServiceName(serviceName);
        const event: UsageEventV1 = {
          schema_version: "1.3",
          event_id: spanEventId(rawSpan.traceId, rawSpan.spanId),
          ts: toSecondPrecisionIso(endMs),
          host_ref: createHmac("sha256", hostSalt).update(`otel:${serviceName}`).digest("hex"),
          user_ref: null,
          // AIM-1168: Claude Code OTel is a coding-tool feed, not first-party
          // app APM. tool=claude_code keeps it on Tools/Overview and off Apps.
          tool: claudeCode ? "claude_code" : "genai_app",
          model: typeof model === "string" && model.length > 0 ? model : null,
          provider:
            typeof spanAttrs.get("gen_ai.system") === "string"
              ? (spanAttrs.get("gen_ai.system") as string)
              : claudeCode
                ? "anthropic"
                : null,
          session_id: rawSpan.traceId,
          service_name: serviceName.slice(0, 128),
          match_flags: [],
          source: "otel",
          status: isErrorStatus(rawSpan.status?.code) ? "error" : "ok",
        };
        if (typeof tokensIn === "number" && tokensIn >= 0) event.tokens_in = tokensIn;
        if (typeof tokensOut === "number" && tokensOut >= 0) event.tokens_out = tokensOut;
        if (startMs !== null && endMs >= startMs) {
          event.duration_ms = Math.round(endMs - startMs);
        }

        events.push(event);
        stats.spansMapped += 1;
      }
    }
  }

  return { events, stats, errors };
}
