#!/usr/bin/env node
/**
 * Validate collector-emitted events against the canonical schema
 * (packages/schema/schema/v1/ai-usage-event.schema.json) using the same
 * AJV setup as the ingest service (services/ingest/src/schema.ts).
 *
 * Sample events are produced by the actual collector code (a python
 * snippet driving cursor_collector), so this proves end-to-end that what
 * the collector builds is what ingest accepts.
 *
 * Usage:  node collectors/cursor/validate_schema.mjs   (from the repo root)
 * Exit 0 = all events valid; exit 1 = any failure.
 */
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");

// Resolve ajv/ajv-formats from the ingest service's install, exactly like
// services/ingest/src/schema.ts does (ajv/dist/2020 for draft 2020-12).
const require = createRequire(join(repoRoot, "services", "ingest", "package.json"));
const Ajv = require("ajv/dist/2020").default;
const addFormats = require("ajv-formats").default;

const schema = JSON.parse(readFileSync(
  join(repoRoot, "packages", "schema", "schema", "v1", "ai-usage-event.schema.json"),
  "utf8"));

// strictRequired off: the schema uses if/then with cross-subschema
// `required`, which strict mode would reject at compile (same as ingest).
const ajv = new Ajv({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
const validate = ajv.compile(schema);

// Generate sample events with the real collector code. AIM_STATE_DIR is a
// throwaway dir so the run touches nothing outside temp.
const PY = String.raw`
import json
from cursor_collector import events, hook

samples = []

# 1. minimal session event (model unobservable -> "unknown" fallback)
samples.append(events.new_event(raw_session_id="conv-1", model=None))

# 2. full usage event: tokens, cost, flags, repo, tool version
samples.append(events.new_event(
    raw_session_id="conv-2", model="gpt-4o", cwd="/home/u/repo",
    tokens_in=1200, tokens_out=300, cost_estimate_usd=0.006,
    flags=["secret:aws-access-key", "pii:email"], tool_version="1.2.3"))

# 3. event built through the hook path (secret in prompt -> flag only)
samples += hook.handle_payload("beforeSubmitPrompt", {
    "conversation_id": "conv-3", "model": "claude-sonnet-4",
    "workspace_roots": ["/home/u/other-repo"],
    "prompt": "use key AKIAIOSFODNN7EXAMPLE",
})

# 4. tool_use event (schema v1.1) via the postToolUse hook path,
#    incl. an MCP-namespaced tool; arguments/output must not survive
samples += hook.handle_payload("postToolUse", {
    "conversation_id": "conv-4", "model": "gpt-4o",
    "tool_name": "Shell", "tool_input": {"command": "npm test"},
    "tool_output": "{\"exitCode\":0}", "duration": 5432,
})
samples.append(events.new_tool_use_event(
    raw_session_id="conv-4", model="gpt-4o",
    tool_calls=[
        events.tool_call_entry("mcp__github__create_issue", count=2,
                               duration_ms=3110),
        events.tool_call_entry("read_file", count=3),
    ]))

print(json.dumps(samples))
`;

const eventsJson = execFileSync("python3", ["-c", PY], {
  cwd: join(here),                       // so `import cursor_collector` resolves
  env: { ...process.env, AIM_STATE_DIR: mkdtempSync(join(tmpdir(), "aim-val-")) },
  encoding: "utf8",
});
const samples = JSON.parse(eventsJson);

let failed = 0;
samples.forEach((ev, i) => {
  const ok = validate(ev);
  if (ok) {
    console.log(`event ${i}: VALID (model=${ev.model}, flags=${ev.match_flags.length})`);
  } else {
    failed++;
    console.error(`event ${i}: INVALID`);
    for (const err of validate.errors ?? []) {
      console.error(`  ${err.instancePath || "(root)"}: ${err.message}`);
    }
  }
});

// Negative control: a content-carrying event must be REJECTED, proving
// additionalProperties:false is really enforced by this setup.
const dirty = { ...samples[0], event_id: crypto.randomUUID(), prompt_text: "leak" };
if (validate(dirty)) {
  failed++;
  console.error("negative control FAILED: out-of-schema field was accepted");
} else {
  console.log("negative control: out-of-schema field correctly rejected");
}

if (failed) {
  console.error(`${failed} validation failure(s)`);
  process.exit(1);
}
console.log(`all ${samples.length} collector events validate against the canonical schema`);
