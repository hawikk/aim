import { createHash, createHmac } from "node:crypto";
import type { UsageEventV1 } from "./schema";
import type { VendorDailyRollup } from "./vendor-admin/types";

/**
 * OTLP/HTTP JSON metrics receiver for Claude Code first-party telemetry
 * (AIM-1168). Anthropic's exporter emits claude_code.* counters
 * (tokens, cost, sessions, loc). Prompt content is redacted by default
 * on their side; we still enforce an attribute allowlist at this boundary.
 *
 * Events: token / cost / session metrics → canonical ai-usage-event
 *   source='otel', tool='claude_code' (NOT genai_app).
 * Rollups: loc / commit / PR / active_time → vendor_admin_daily (claude_otel).
 *
 * The OTLP body is never archived raw.
 */

const RESOURCE_ATTRIBUTE_ALLOWLIST = new Set(["service.name"]);

const DATAPOINT_ATTRIBUTE_ALLOWLIST = new Set([
  "session.id",
  "model",
  "type",
  "user.account_uuid",
  "organization.id",
  "terminal.type",
]);

const CLAUDE_EVENT_METRICS = new Set([
  "claude_code.token.usage",
  "claude_code.cost.usage",
  "claude_code.session.count",
]);

const CLAUDE_ROLLUP_METRICS = new Set([
  "claude_code.lines_of_code.count",
  "claude_code.pull_request.count",
  "claude_code.commit.count",
  "claude_code.active_time.total",
]);

export const MAX_OTLP_DATAPOINTS = 5000;

export interface OtlpMetricMapStats {
  datapointsReceived: number;
  datapointsMapped: number;
  datapointsSkipped: number;
  datapointsRejected: number;
  attributesDropped: number;
}

export interface OtlpMetricMapResult {
  events: UsageEventV1[];
  rollups: VendorDailyRollup[];
  stats: OtlpMetricMapStats;
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
    else if (typeof v.intValue === "string" && /^-?\d+$/.test(v.intValue))
      out.set(entry.key, Number.parseInt(v.intValue, 10));
    else if (typeof v.doubleValue === "number") out.set(entry.key, v.doubleValue);
    else if (typeof v.boolValue === "boolean") out.set(entry.key, v.boolValue);
  }
  return out;
}

function unixNanoToMs(raw: unknown): number | null {
  if (typeof raw === "number" && Number.isFinite(raw)) return raw / 1e6;
  if (typeof raw === "string" && /^\d+$/.test(raw)) return Number(raw) / 1e6;
  return null;
}

function toSecondPrecisionIso(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().slice(0, 19) + "Z";
}

function toDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

function metricEventId(seed: string): string {
  const hex = createHash("sha256").update(`aimon-otel-metric:${seed}`).digest("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function hmacHex(salt: string, value: string): string {
  return createHmac("sha256", salt).update(value).digest("hex");
}

function numericPointValue(point: Record<string, unknown>): number | null {
  if (typeof point.asInt === "number") return point.asInt;
  if (typeof point.asInt === "string" && /^-?\d+$/.test(point.asInt)) {
    return Number.parseInt(point.asInt, 10);
  }
  if (typeof point.asDouble === "number" && Number.isFinite(point.asDouble)) {
    return point.asDouble;
  }
  return null;
}

function collectDataPoints(metric: Record<string, unknown>): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const kind of ["sum", "gauge", "histogram"] as const) {
    const block = metric[kind];
    if (!block || typeof block !== "object") continue;
    const dps = (block as { dataPoints?: unknown }).dataPoints;
    if (!Array.isArray(dps)) continue;
    for (const dp of dps) {
      if (dp && typeof dp === "object") out.push(dp as Record<string, unknown>);
    }
  }
  return out;
}

function isClaudeCodeService(name: unknown): boolean {
  return typeof name === "string" && /^claude[-_]?code$/i.test(name.trim());
}

export function isClaudeCodeMetricName(name: unknown): boolean {
  return typeof name === "string" && name.startsWith("claude_code.");
}

/**
 * Map an OTLP ExportMetricsServiceRequest (JSON) into Claude Code usage
 * events + optional daily rollups. Non-Claude metrics are skipped.
 */
export function mapOtlpMetricsRequest(body: unknown, hostSalt: string): OtlpMetricMapResult {
  const stats: OtlpMetricMapStats = {
    datapointsReceived: 0,
    datapointsMapped: 0,
    datapointsSkipped: 0,
    datapointsRejected: 0,
    attributesDropped: 0,
  };
  const events: UsageEventV1[] = [];
  const rollupByDay = new Map<string, VendorDailyRollup>();
  const errors: string[] = [];

  const resourceMetrics =
    body !== null && typeof body === "object"
      ? (body as { resourceMetrics?: unknown }).resourceMetrics
      : undefined;
  if (!Array.isArray(resourceMetrics)) {
    return {
      events,
      rollups: [],
      stats,
      errors: ["body must be an OTLP ExportMetricsServiceRequest with resourceMetrics[]"],
    };
  }

  const reject = (reason: string) => {
    stats.datapointsRejected += 1;
    if (errors.length < 25) errors.push(reason);
  };

  for (const rm of resourceMetrics) {
    if (!rm || typeof rm !== "object") continue;
    const resourceAttrs = extractAttributes(
      (rm as { resource?: { attributes?: unknown } }).resource?.attributes,
      RESOURCE_ATTRIBUTE_ALLOWLIST,
      stats,
    );
    const serviceNameRaw = resourceAttrs.get("service.name");
    const serviceName =
      typeof serviceNameRaw === "string" && serviceNameRaw.length > 0
        ? serviceNameRaw.slice(0, 128)
        : "claude-code";

    const scopeMetrics = (rm as { scopeMetrics?: unknown }).scopeMetrics;
    if (!Array.isArray(scopeMetrics)) continue;

    for (const sm of scopeMetrics) {
      const metrics = (sm as { metrics?: unknown } | null)?.metrics;
      if (!Array.isArray(metrics)) continue;

      for (const rawMetric of metrics as Array<Record<string, unknown>>) {
        const name = rawMetric?.name;
        const claude = isClaudeCodeMetricName(name) || isClaudeCodeService(serviceName);
        if (!claude) {
          // Count attributes so a misconfigured exporter still shows drops.
          for (const dp of collectDataPoints(rawMetric ?? {})) {
            extractAttributes(dp.attributes, DATAPOINT_ATTRIBUTE_ALLOWLIST, stats);
          }
          continue;
        }
        if (typeof name !== "string") continue;

        for (const dp of collectDataPoints(rawMetric)) {
          stats.datapointsReceived += 1;
          if (stats.datapointsReceived > MAX_OTLP_DATAPOINTS) {
            errors.push(`datapoint count exceeds ${MAX_OTLP_DATAPOINTS}`);
            return { events, rollups: [...rollupByDay.values()], stats, errors };
          }

          const attrs = extractAttributes(dp.attributes, DATAPOINT_ATTRIBUTE_ALLOWLIST, stats);
          const endMs =
            unixNanoToMs(dp.timeUnixNano) ?? unixNanoToMs(dp.startTimeUnixNano);
          if (endMs === null) {
            reject("metric datapoint missing timeUnixNano");
            continue;
          }
          const value = numericPointValue(dp);
          if (value === null || value < 0) {
            reject("metric datapoint missing numeric value");
            continue;
          }

          const day = toDay(endMs);
          const model = typeof attrs.get("model") === "string" ? (attrs.get("model") as string) : null;
          const type = typeof attrs.get("type") === "string" ? (attrs.get("type") as string) : "";
          const sessionRaw =
            typeof attrs.get("session.id") === "string" ? (attrs.get("session.id") as string) : "";
          const orgId =
            typeof attrs.get("organization.id") === "string"
              ? (attrs.get("organization.id") as string)
              : "fleet";
          const accountUuid =
            typeof attrs.get("user.account_uuid") === "string"
              ? (attrs.get("user.account_uuid") as string)
              : "";

          if (CLAUDE_ROLLUP_METRICS.has(name)) {
            let rollup = rollupByDay.get(day);
            if (!rollup) {
              rollup = {
                day,
                feed: "claude_otel",
                tool: "claude_code",
                tool_raw: null,
                active_users: 0,
                engaged_users: 0,
                sessions: 0,
                tokens_in: 0,
                tokens_out: 0,
                cost_usd: 0,
                loc_suggested: 0,
                loc_accepted: 0,
                loc_committed_ai: 0,
                extras: {},
              };
              rollupByDay.set(day, rollup);
            }
            if (name === "claude_code.lines_of_code.count") {
              if (type === "removed") {
                /* volume only — not a content field */
              } else {
                rollup.loc_committed_ai += Math.floor(value);
                rollup.loc_suggested += Math.floor(value);
              }
            } else if (name === "claude_code.commit.count") {
              rollup.extras.commits = asNonNeg(Number(rollup.extras.commits ?? 0) + value);
            } else if (name === "claude_code.pull_request.count") {
              rollup.extras.pull_requests = asNonNeg(Number(rollup.extras.pull_requests ?? 0) + value);
            }
            stats.datapointsMapped += 1;
            continue;
          }

          if (!CLAUDE_EVENT_METRICS.has(name)) {
            stats.datapointsSkipped += 1;
            continue;
          }

          const sessionSeed = sessionRaw
            ? hmacHex(hostSalt, `${day}:${sessionRaw}`)
            : hmacHex(hostSalt, `claude-code:${day}:${name}:${model ?? ""}:${type}`);
          const event: UsageEventV1 = {
            schema_version: "1.3",
            event_id: metricEventId(`${name}:${endMs}:${sessionSeed}:${type}:${value}`),
            ts: toSecondPrecisionIso(endMs),
            host_ref: hmacHex(hostSalt, `otel:claude-code:${orgId}`),
            user_ref: accountUuid ? hmacHex(hostSalt, accountUuid) : null,
            tool: "claude_code",
            model,
            provider: "anthropic",
            session_id: sessionSeed,
            service_name: "claude-code",
            match_flags: [],
            source: "otel",
            status: "ok",
          };
          if (name === "claude_code.token.usage") {
            const n = Math.floor(value);
            if (type === "output") event.tokens_out = n;
            else event.tokens_in = n; // input + cacheRead + cacheCreation
          } else if (name === "claude_code.cost.usage") {
            event.cost_estimate_usd = value;
          }

          events.push(event);
          stats.datapointsMapped += 1;
        }
      }
    }
  }

  return { events, rollups: [...rollupByDay.values()], stats, errors };
}

function asNonNeg(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) return value;
  return 0;
}
