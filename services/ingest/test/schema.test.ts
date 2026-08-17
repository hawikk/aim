import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { validateEvent, type UsageEventV1 } from "../src/schema";

const examplesDir = join(
  __dirname,
  "..",
  "..",
  "..",
  "packages",
  "schema",
  "examples",
);

function loadExample(name: string): UsageEventV1 {
  return JSON.parse(readFileSync(join(examplesDir, name), "utf8")) as UsageEventV1;
}

describe("validateEvent", () => {
  test.each(["valid-claude-code.json", "valid-cursor.json", "valid-kilo-code.json"])(
    "accepts schema example %s",
    (name) => {
      const result = validateEvent(loadExample(name));
      expect(result.errors).toEqual([]);
      expect(result.valid).toBe(true);
    },
  );

  test("rejects unsupported major schema_version loudly, naming the version", () => {
    const event = { ...loadExample("valid-claude-code.json"), schema_version: "99.0" };
    const result = validateEvent(event);
    expect(result.valid).toBe(false);
    expect(result.errors.join(" ")).toContain("99.0");
  });

  test("does not echo content smuggled through schema_version", () => {
    const canary = "9.0 SCHEMA-VERSION-CANARY do not store this prompt text";
    const event = { ...loadExample("valid-claude-code.json"), schema_version: canary };
    const result = validateEvent(event);
    expect(result.valid).toBe(false);
    // Rejection errors are persisted to rejected_events and the archive stub,
    // so an unbounded echo here would be a content-egress path.
    expect(result.errors.join(" ")).not.toContain("SCHEMA-VERSION-CANARY");
    expect(result.errors.join(" ")).toContain("<malformed>");
  });

  test("does not echo content smuggled through a property name", () => {
    const event = {
      ...loadExample("valid-claude-code.json"),
      ["PROPERTY-NAME-CANARY leaking an entire prompt body through the key"]: 1,
    };
    const result = validateEvent(event);
    expect(result.valid).toBe(false);
    expect(result.errors.join(" ")).not.toContain("PROPERTY-NAME-CANARY");
  });

  test("rejects a missing required field", () => {
    const event = loadExample("valid-claude-code.json") as unknown as Record<string, unknown>;
    delete event.event_id;
    const result = validateEvent(event);
    expect(result.valid).toBe(false);
    expect(result.errors.join(" ")).toContain("event_id");
  });

  test("rejects unexpected properties without echoing values", () => {
    const event = {
      ...loadExample("valid-claude-code.json"),
      prompt_text: "super secret prompt content",
    };
    const result = validateEvent(event);
    expect(result.valid).toBe(false);
    expect(result.errors.join(" ")).toContain("prompt_text");
    expect(result.errors.join(" ")).not.toContain("super secret prompt content");
  });

  test("rejects the invalid example that carries prompt text", () => {
    const result = validateEvent(loadExample("invalid-contains-prompt-text.json"));
    expect(result.valid).toBe(false);
  });

  test("accepts the tool_use example (schema v1.1)", () => {
    const result = validateEvent(loadExample("valid-tool-use.json"));
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });

  test("rejects a tool_calls entry carrying arguments (metadata-only guarantee)", () => {
    const result = validateEvent(loadExample("invalid-tool-call-arguments.json"));
    expect(result.valid).toBe(false);
    expect(result.errors.join(" ")).toContain("arguments");
    // The arguments value must never echo into the error text.
    expect(result.errors.join(" ")).not.toContain("cat ~/.aws/credentials");
  });

  test("rejects event_type 'tool_use' without tool_calls", () => {
    const event = loadExample("valid-tool-use.json") as unknown as Record<string, unknown>;
    delete event.tool_calls;
    const result = validateEvent(event);
    expect(result.valid).toBe(false);
    expect(result.errors.join(" ")).toContain("tool_calls");
  });

  test("rejects non-object payloads", () => {
    expect(validateEvent(null).valid).toBe(false);
    expect(validateEvent("not an event").valid).toBe(false);
    expect(validateEvent(42).valid).toBe(false);
  });

  // AIM-104: model + token fields are top-level operational metadata in the
  // canonical schema (since v1.0); ingest must accept v1.x events carrying
  // them and reject malformed token values outright.
  describe("model/token fields (AIM-104)", () => {
    test.each(["1.0", "1.1", "1.2"])("accepts schema_version %s with model + tokens", (v) => {
      const event = { ...loadExample("valid-cursor.json"), schema_version: v };
      const result = validateEvent(event);
      expect(result.errors).toEqual([]);
      expect(result.valid).toBe(true);
    });

    test("accepts a proxy event with model null and tokens omitted", () => {
      const event = {
        ...loadExample("valid-claude-code.json"),
        model: null,
        source: "proxy",
      } as unknown as Record<string, unknown>;
      delete event.tokens_in;
      delete event.tokens_out;
      delete event.repo_ref;
      const result = validateEvent(event);
      expect(result.errors).toEqual([]);
      expect(result.valid).toBe(true);
    });

    test.each([
      ["string tokens_in", { tokens_in: "5210" }],
      ["fractional tokens_in", { tokens_in: 52.5 }],
      ["negative tokens_out", { tokens_out: -1 }],
      ["null tokens_in", { tokens_in: null }],
      ["boolean tokens_out", { tokens_out: true }],
    ])("rejects malformed token field: %s", (_label, patch) => {
      const event = { ...loadExample("valid-cursor.json"), ...patch };
      const result = validateEvent(event);
      expect(result.valid).toBe(false);
      expect(result.errors.join(" ")).toMatch(/tokens_(in|out)/);
    });

    test("rejects legacy metrics-object fields (superseded schemas/event.v1.json shape)", () => {
      const event = {
        ...loadExample("valid-cursor.json"),
        metrics: { model: "claude-sonnet-4-5", tokens_in: 100, tokens_out: 10 },
      };
      const result = validateEvent(event);
      expect(result.valid).toBe(false);
      expect(result.errors.join(" ")).toContain("metrics");
      // The token values smuggled inside must never echo into the error text.
      expect(result.errors.join(" ")).not.toContain("claude-sonnet-4-5");
    });
  });

  // AIM-103 (schema v1.4): proxy-path source-class attribution and network
  // volume metadata. traffic_class is a fixed 3-value enum — anything else
  // (e.g. a raw subnet name) must be rejected, not stored.
  describe("source-class attribution (AIM-103)", () => {
    test("accepts the v1.4 proxy app-LLM example", () => {
      const result = validateEvent(loadExample("valid-proxy-app-llm.json"));
      expect(result.errors).toEqual([]);
      expect(result.valid).toBe(true);
    });

    test("rejects an out-of-enum traffic_class", () => {
      const result = validateEvent(loadExample("invalid-traffic-class.json"));
      expect(result.valid).toBe(false);
      expect(result.errors.join(" ")).toContain("traffic_class");
    });

    test.each([
      ["fractional bytes_down", { bytes_down: 52.5 }],
      ["negative bytes_up", { bytes_up: -1 }],
      ["string http_status", { http_status: "200" }],
    ])("rejects malformed network metadata: %s", (_label, patch) => {
      const event = { ...loadExample("valid-proxy-app-llm.json"), ...patch };
      const result = validateEvent(event);
      expect(result.valid).toBe(false);
    });

    test("accepts null/omitted network metadata (source cannot observe it)", () => {
      const event = loadExample("valid-proxy-app-llm.json") as unknown as Record<string, unknown>;
      event.bytes_up = null;
      event.http_status = null;
      delete event.bytes_down;
      delete event.duration_ms;
      const result = validateEvent(event);
      expect(result.errors).toEqual([]);
      expect(result.valid).toBe(true);
    });
  });
});
