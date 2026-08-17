# kilo-collector — Kilo Code endpoint collector (AIM-22)

Metadata-only usage collector for Kilo Code (VS Code extension, Roo
Code/Cline lineage) on Windows / WSL / Linux. Pure Python 3 stdlib — no
third-party dependencies, same as the Claude Code collector, so the
endpoint package stays trivially auditable and Intune-shippable.

## What it collects (and what it never collects)

Collects **metadata only**, per the locked content policy (AIM-16) and the
ratified event schema (`packages/schema/schema/v1/ai-usage-event.schema.json`,
AIM-18):

- model (best effort, see gap report below), derived provider, token usage
  (`tokens_in`/`tokens_out`; cache-read folds into `tokens_in` per v1),
  provider-reported `cost_estimate_usd`, pseudonymized host/workspace refs
  (HMAC-SHA256), tool version, timestamps
- `match_flags` set by local secret/PII pattern matchers (unified ruleset,
  canonical source `collectors/matcher-ruleset/matchers.py`, AIM-91)
- one event per completed API request (delta-emitted, so dashboards can sum)
- per-task tool-call aggregates as `event_type="tool_use"` events and MCP
  server config inventory as `event_type="inventory"` events (schema v1.2,
  AIM-97 — see below)

Unlike Claude Code, Kilo Code records the **provider-reported cost** per
request, which a platform-side static price table cannot reproduce across
Kilo's many providers (OpenRouter, Bedrock, direct APIs) — so this
collector does send `cost_estimate_usd` when the tool reports it.

It **never** transmits prompt text, conversation content, or file contents.
Kilo's task logs contain all of these; they are read locally, scanned for
secret/PII patterns, and discarded — only detector names leave the machine.
Ingest rejects out-of-schema fields whole, so a content leak would fail
closed.

## Tool-call capture & MCP inventory (AIM-97)

Mirrors the Claude Code collector's AIM-86 pattern, adapted to Kilo's
on-disk formats (schema v1.2 events).

**Tool calls.** Tool activity in `ui_messages.json` is counted per task
and emitted as one `event_type="tool_use"` event per task per scan when
there are new calls — independently of request deltas, so a scan with only
tool activity still produces an event. Sources:

- `say == "tool"` entries: `text` is a JSON string naming the tool in its
  `tool` field (Roo Code/Cline lineage names: `readFile`,
  `editedExistingFile`, `writeToFile`, `executeCommand`, `searchFiles`,
  `applyDiff`, `browserAction`, `useMcpTool`, ...). One call per entry.
- MCP activity: `ask == "use_mcp_server"` and
  `say == "mcp_server_request_started"` entries name the server/tool in
  their `text` JSON (`serverName`/`toolName`). Every MCP call is
  `action_class="mcp_call"` with the server id in `mcp_server`.
  `say == "mcp_server_response"` entries are the second half of the
  request pair and are deliberately NOT counted (would double-count).
  `tool_use` blocks in `api_conversation_history.json` are NOT read —
  `ui_messages.json` is the sole source of truth.

What IS captured, per (tool, MCP server) per scan window (`tool_calls[]`):
tool name, MCP server id, `action_class` (`fs_read` / `fs_write` /
`shell` / `network` / `mcp_call` / `other`; unknown tool names fall back
to `other`, never a guess), invocation count (delta-emitted against the
checkpoint), and `duration_ms` — currently always `null` (schema-valid):
pairing request/response entries across incremental scans would need
pending-call state in the checkpoint.

What is NOT captured, ever: tool arguments, command lines, file paths,
URLs, tool output. Only the name fields of the `text` JSON are read; the
path/command/content keys in the same payload are never touched. The
schema's `additionalProperties: false` on `tool_calls` entries makes any
attempt to attach arguments fail at ingest, and `events.validate()`
rejects them locally first.

**MCP inventory.** The collector also reads Kilo's MCP config files and
emits one `event_type="inventory"` event per scan in which the configured
set changes (a hash of the sorted (name, scope) list is checkpointed;
steady state emits nothing, and an empty list is an explicit "no servers
configured" statement):

- `<globalStorage>/kilocode.kilo-code/settings/mcp_settings.json` — scope
  `user`. The `mcpServers` object KEYS are the server names.
- `<workspace>/.kilocode/mcp.json` — scope `project`, same shape; project
  scope wins when a name is configured in both (Kilo's own resolution
  rule). Workspaces are reused from the per-task checkpoint fragments
  (already extracted from `api_conversation_history.json`
  `<environment_details>` blocks) — no extra parsing pass, and workspace
  paths never land on an event.

Only the server NAMES and scopes are read — never commands, args, URLs,
or env values (env may hold secrets). Inventory events carry
`model: null`, `provider: null`, no token fields, and a synthetic
`session_id` (`inv_<utc-date>_<host_ref[:12]>`), since config inventory
is not LLM traffic.

## How it works

Kilo Code has no hook/callback API for third parties, so the collector
**polls on-disk telemetry from both product surfaces** (AIM-647):

### IDE surface (VS Code / Cursor extension)

Per task, under the extension's VS Code `globalStorageUri`
([Kilo Code file-locations doc](https://github.com/Kilo-Org/kilocode-legacy/blob/main/docs/legacy-ides/getting-started/file-locations.md)):

```
<VS Code user-data>/globalStorage/kilocode.kilo-code/tasks/<taskId>/
    ui_messages.json               # per-request token/cost telemetry
    api_conversation_history.json  # content; local-only (workspace path, flags)
```

`ui_messages.json` holds UI events; telemetry lives in entries with
`say == "api_req_started"`, whose `text` is JSON with `tokensIn`,
`tokensOut`, `cacheReads`, `cacheWrites`, `cost`, `apiProtocol` and the
`request` prompt text. In-flight requests have no token fields yet and are
revisited on the next pass (checkpoint tracks per-task processed count, so
emission is an exact-once-per-request delta).

Storage roots discovered: VS Code desktop variants (`Code`, `Code -
Insiders`, `VSCodium`, `Cursor`), remote extension hosts
(`.vscode-server*`, **`.cursor-server`**), and the JetBrains wrapper
(`~/.kilocode/globalStorage`). Override with `AIM_KILO_STORAGE_DIR`
(also the answer for fleets using Kilo's `kilo-code.customStoragePath`
setting).

### CLI surface (standalone `kilo` binary)

```
~/.local/share/kilo/kilo.db   # XDG data home; override AIM_KILO_CLI_DB
```

The CLI is a separate product binary (`~/.kilo/bin/kilo` / PATH `kilo`)
with its own SQLite session store — not the VS Code task JSON. The
collector copies the live DB to a temp file, reads `session` token/cost
columns read-only, optionally scans `message`/`part` text for matchers
locally, and emits usage events with `tool_version` prefixed `cli/` so
dashboards can prove the surface. See `cli_sessions.py` and
`docs/aim-647-dual-surface-completeness.md`.

Session ids: Kilo task ids are long-lived, so per the schema's `session_id`
rule they are re-hashed per UTC day — `HMAC(utc-date || task_id)` — and
cannot be profiled across days.

## Commands

```
python -m kilo_collector scan-once   # one pass; scheduled-task/cron deployments
python -m kilo_collector watch       # daemon: poll every N seconds (default 60)
python -m kilo_collector flush       # drain local spool to ingestion API
```

Spool/flush semantics, managed config file, env vars
(`AIM_INGEST_URL`, `AIM_COLLECTOR_TOKEN`, `AIM_STATE_DIR`,
`AIM_CONFIG_FILE`, `AIM_HASH_SALT`), and batch-envelope identity attestation
(`device_id` config key / `AIM_DEVICE_ID` env / `dsregcmd`, AIM-58) are
identical to the Claude Code collector — see
`collectors/claude-code/README.md`. Deployment: Windows
scheduled task or Linux cron/systemd user timer running `scan-once`.

## Gap report (acceptance criterion 2)

Local telemetry is **sufficient for the v1 event contract**, with caveats:

1. **Model is not guaranteed on disk (IDE).** The `api_req_started` payload
   carries `modelId` in current Kilo Code versions; when absent we fall
   back to `api_conversation_history.json` (some versions store a `model`
   key on messages). If neither is present the event emits `model: null`
   (schema-valid; `provider` also null).
2. **Provider is derived from the model name**, not observed directly —
   Kilo's `apiProtocol` field describes the wire protocol, not the
   provider. Good enough for spend/usage views; provider-accurate
   attribution would need the API config (extension secrets — not
   readable without Kilo's own APIs).
3. **CLI tool_use depth (AIM-647 residual).** The CLI SQLite path emits
   usage (tokens/cost/model) only. Tool-call aggregates from CLI `part`
   frames are not classified yet — the IDE path remains the deep
   tool_use source for extension tasks.

Everything else the issue asks for (tokens, cost, task/request counts,
repo, flags, **both IDE and CLI surfaces**) is available from local
telemetry. Dual-surface proof: `python3 scripts/aim-647-dual-surface-proof.py`
and `tests/test_cli_sessions.py`.

## Tests

```
python3 -m unittest discover -s tests -v
```
