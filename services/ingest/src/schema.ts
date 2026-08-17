import Ajv, { type ErrorObject, type ValidateFunction } from "ajv/dist/2020";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * AI usage event, schema v1 — the AIM-18 metadata-only contract
 * (packages/schema/schema/v1/ai-usage-event.schema.json). This is the shape
 * collectors (AIM-20) emit. No field may carry prompt/response text or code.
 */
export interface UsageEventV1 {
  schema_version: string;
  event_id: string;
  ts: string;
  host_ref: string;
  user_ref?: string | null;
  tool: "claude_code" | "cursor" | "kilo_code" | "kimi_code" | "grok_build" | "other" | "genai_app";
  tool_raw?: string;
  tool_version?: string;
  model?: string | null;
  provider?: string | null;
  session_id: string;
  tokens_in?: number;
  tokens_out?: number;
  cost_estimate_usd?: number;
  repo_ref?: string | null;
  match_flags: MatchFlag[];
  source: "proxy" | "endpoint" | "otel";
  /** Application identity (schema v1.3, AIM-105); required when source is "otel". */
  service_name?: string;
  /** LLM call wall time in ms (schema v1.3, AIM-105), from OTel span duration. */
  duration_ms?: number;
  /** LLM call outcome (schema v1.3, AIM-105): never carries an error message. */
  status?: "ok" | "error";
  /** Source-class attribution (schema v1.4, AIM-103), proxy events only. */
  traffic_class?: "application" | "employee" | "unknown";
  /** Request/response volume in bytes (schema v1.4, AIM-103). */
  bytes_up?: number | null;
  bytes_down?: number | null;
  /** HTTP status of the proxied transaction (schema v1.4, AIM-103). */
  http_status?: number | null;
  /** Event kind (schema v1.1/v1.2). Absent means "usage". */
  event_type?: "usage" | "tool_use" | "inventory";
  /** Tool-call aggregates; required when event_type is "tool_use". */
  tool_calls?: ToolCall[];
  /** Configured MCP servers; required when event_type is "inventory" (v1.2, AIM-97). */
  configured_mcp_servers?: ConfiguredMcpServer[];
  /** Endpoint enforcement audit record (v1.5, AIM-110; v1.6 AIM-111). Rides in the payload JSONB. */
  enforcement?: EnforcementRecord;
  /** Endpoint enforcement coverage marker (v1.7, AIM-110): the shadow bake's denominator. */
  enforcement_posture?: EnforcementPosture;
}

/**
 * Endpoint enforcement coverage marker (schema v1.7, AIM-110). Emitted on
 * every event by an enforcement-aware hook, decision or not. Without it a
 * zero `enforcement` count cannot be distinguished from an endpoint that
 * never ran the rules, which is why the shadow-bake report reads a missing
 * posture as NO COVERAGE rather than as a clean result.
 */
export interface EnforcementPosture {
  policy: "absent" | "loaded";
  evaluated: boolean;
  mode?: "shadow" | "enforce";
  policy_hash?: string;
}

/**
 * Endpoint inline-enforcement audit record (schema v1.5, AIM-110).
 * Metadata-only: action + rule id + policy hash — never the blocked payload.
 * 'confirmed' (v1.6, AIM-111): a confirm-prompt rule (pii-in-prompt)
 * challenged and the user resubmitted to confirm; the prompt proceeded.
 */
export interface EnforcementRecord {
  action: "blocked" | "would_block" | "confirmed";
  rule_id: string;
  policy_hash?: string;
}

/**
 * One tool-call aggregate entry (schema v1.1, AIM-86). Metadata-only: the
 * schema forbids arguments/paths/output via additionalProperties:false.
 */
export interface ToolCall {
  tool_name: string;
  action_class: "fs_read" | "fs_write" | "shell" | "network" | "mcp_call" | "other";
  count: number;
  mcp_server?: string | null;
  duration_ms?: number | null;
}

/**
 * One configured MCP server entry (schema v1.2, AIM-97). Metadata-only:
 * server name + config scope; commands/args/env are forbidden by
 * additionalProperties:false.
 */
export interface ConfiguredMcpServer {
  name: string;
  scope: "user" | "project";
}

export interface MatchFlag {
  detector: string;
  category: "secret" | "pii" | "policy";
  severity?: "low" | "medium" | "high";
}

export interface ValidationResult {
  valid: boolean;
  /** Human-readable validation errors, empty when valid. Never contains payload values. */
  errors: string[];
}

// The AIM-18 schema file is the single source of truth; the service reads it
// from the repo checkout. Deployments outside the repo set SCHEMA_PATH.
const schemaPath =
  process.env.SCHEMA_PATH ??
  join(__dirname, "..", "..", "..", "packages", "schema", "schema", "v1", "ai-usage-event.schema.json");
const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as Record<string, unknown>;

// strictRequired off: the AIM-18 schema uses if/then with cross-subschema
// `required` (valid JSON Schema), which strict mode would reject at compile.
const ajv = new Ajv({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);

const compiled: ValidateFunction = ajv.compile(schema);

/**
 * Longest client-controlled token we will ever echo back into an error string.
 * Rejection errors are persisted (rejected_events, and the archive stub), so
 * anything echoed here is a content-egress path: a collector that puts prompt
 * text in a property name or a schema_version must not get it stored.
 */
const MAX_ECHO_LENGTH = 40;
const SAFE_ECHO_RE = /^[0-9A-Za-z._-]+$/;

/** Bounded, character-restricted echo of a client-supplied token. */
function safeEcho(value: unknown): string {
  if (typeof value !== "string") return `<${typeof value}>`;
  if (value.length === 0) return "<empty>";
  if (value.length > MAX_ECHO_LENGTH || !SAFE_ECHO_RE.test(value)) return "<malformed>";
  return value;
}

function formatError(err: ErrorObject): string {
  const where = err.instancePath || "(root)";
  // ajv messages include the offending *value* for some keywords; strip params
  // so we never echo payload content into logs or API responses.
  if (err.keyword === "additionalProperties") {
    const prop = (err.params as { additionalProperty?: string }).additionalProperty;
    return `${where}: unexpected property '${safeEcho(prop)}'`;
  }
  return `${where}: ${err.message ?? err.keyword}`;
}

/** Major version of a `major.minor` schema_version string. */
function majorVersion(schemaVersion: unknown): string | null {
  if (typeof schemaVersion !== "string") return null;
  const m = /^(\d+)\./.exec(schemaVersion);
  return m?.[1] ?? null;
}

export function validateEvent(event: unknown): ValidationResult {
  // Fail loudly on unsupported major versions before detailed validation.
  if (
    typeof event === "object" &&
    event !== null &&
    "schema_version" in event &&
    majorVersion((event as { schema_version?: unknown }).schema_version) !== "1"
  ) {
    const v = (event as { schema_version?: unknown }).schema_version;
    return { valid: false, errors: [`unsupported schema_version: ${safeEcho(v)}`] };
  }
  const ok = compiled(event);
  if (ok) return { valid: true, errors: [] };
  return { valid: false, errors: (compiled.errors ?? []).map(formatError) };
}
