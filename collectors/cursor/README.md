# cursor-collector — Cursor endpoint collector (AIM-21)

Metadata-only usage collector for Cursor on Windows / WSL / Linux.
Pure Python 3.9+ stdlib. No third-party dependencies — deliberate, so the
endpoint package stays trivially auditable and easy to ship via Intune.

## What it collects (and what it never collects)

Collects **metadata only**, per the locked content policy (AIM-16) and the
ratified event schema (`packages/schema/schema/v1/ai-usage-event.schema.json`,
AIM-18):

- model (when observable), token usage (`tokens_in`/`tokens_out`) when the
  surface carries counts, pseudonymized repo/host refs (HMAC-SHA256), tool
  version, timestamps
- tool-call metadata (`event_type: "tool_use"`, schema v1.1): tool name,
  coarse action class, count, duration, MCP server id — see
  "Tool-call capture (AIM-86)" below
- `match_flags` set by local secret/PII pattern matchers
- `cost_estimate_usd` only when token counts AND a known model are
  observable (price table in `pricing.py`)

It **never** transmits prompt text, tool input/output, response text, file
contents, or code. Secret/PII matching runs on the endpoint; only detector
names/categories leave the machine. Ingest rejects out-of-schema fields
whole (`additionalProperties: false`), so a content leak would fail closed,
not land in storage.

Pseudonymization details:

- `host_ref`: HMAC-SHA256 of the hostname; `repo_ref`: HMAC-SHA256 of the
  normalized workspace path. Salt from `AIM_HASH_SALT` env → managed config
  `hash_salt` → per-install random fallback in the state dir.
- `session_id`: Cursor conversation ids are long-lived, so they are
  re-hashed per UTC day — `HMAC(utc-date || raw_id)` — as the schema
  requires. Events cannot be profiled across days.
- `user_ref` is always `null` (identity mapping is a separate service,
  AIM-24/AIM-38).

## How it works

Two collection paths, both feeding one local spool:

1. **Hooks** (`hook <event>` subcommand) — registered in the user-level
   `~/.cursor/hooks.json` for `sessionStart`, `sessionEnd`,
   `beforeSubmitPrompt`, `afterAgentResponse`, `postToolUse`. Cursor pipes
   a JSON payload to stdin; the collector converts it to one v1 event.
   Prompt/tool text fields are scanned locally for secret/PII patterns and
   then discarded — only flags survive. Payload fields vary by Cursor
   version, so extraction is defensive: take what exists, tolerate
   everything missing. The hook always exits 0; a broken collector must
   never break an engineer's session.
2. **Passive state.vscdb scan** (`scan-once` / `watch` subcommands) —
   reads Cursor's local SQLite state (`globalStorage/state.vscdb` and
   `workspaceStorage/*/state.vscdb`, `ItemTable` keys
   `aiService.generations`, `aiService.prompts`, `composer.composerData`)
   and delta-emits usage events for new entries, resumable via a
   checkpoint in the state dir. The live db is **copied to a temp file
   first** and opened read-only, so Cursor's database is never locked or
   mutated. Missing dbs/keys emit nothing and exit 0; unparseable values
   are skipped, never fatal.

## Tool-call capture (AIM-86)

Schema v1.1 added optional `event_type` / `tool_calls` fields. The
collector emits `event_type: "tool_use"` events from the **`postToolUse`
hook** — the one surface where Cursor documents structured tool-call data
(`tool_name`, `duration`; it fires for every agent tool, built-in and MCP).

What IS captured per tool call, metadata only:

- `tool_name`: the tool identifier as Cursor names it (`Shell`, `Read`,
  `Write`, `Grep`, `Delete`, older internal names like `run_terminal_cmd`
  / `edit_file` / `read_file` are mapped too). For MCP tools named in the
  `mcp__<server>__<tool>` convention, the name is split: tool part into
  `tool_name`, server id into `mcp_server`.
- `action_class`: coarse capability class — file reads/searches →
  `fs_read`, edits/writes/deletes → `fs_write`, command execution →
  `shell`, web fetch/search → `network`, MCP calls → `mcp_call`, anything
  unrecognized → `other` (never guessed).
- `count` (1 per hook invocation) and `duration_ms` when the payload
  carries it. Secret/PII flags derived from the local scan of the payload
  ride along in `match_flags`.

What is NEVER captured: tool arguments, command lines, file paths, tool
output, or results. `tool_input`/`tool_output` are scanned locally for
secret/PII patterns and dropped; `tool_calls` entries are
`additionalProperties: false` in the schema, so arguments would fail
ingest validation even if attached. A seeded-string regression guard lives
in `tests/test_tool_use.py`.

What is NOT captured (documented limits):

- **state.vscdb does not expose tool calls reliably.** The keys read by
  the passive scan (`aiService.generations`, `aiService.prompts`,
  `composer.composerData`) are request/response and conversation-metadata
  records. Bubble-level tool records live in a separate undocumented
  surface (`cursorDiskKV` blobs) that we deliberately do not parse — see
  the note in `vscdb.py`. Unblock condition: Cursor stabilizes/documents
  that schema or ships an export API.
- **No hook, no event**: tool calls are only seen on devices where the
  collector's hooks are installed; `postToolUse` firing unreliably
  (background/cloud agents — see Known limitations) undercounts here too.
- **Failed/denied tool calls** are reported via the separate
  `postToolUseFailure` hook, which the collector does not register yet.
- **MCP server attribution** exists only when the tool name is namespaced
  (`mcp__server__tool`); un-namespaced MCP tool names classify as
  `other` with `mcp_server: null` rather than a guess.

## MCP config inventory (AIM-97 / AIM-570)

On each `scan-once` / `watch` pass the collector also reads Cursor MCP
config and emits one `event_type="inventory"` event (schema v1.2) when
the configured server set changes — name + scope only:

- `~/.cursor/mcp.json` → scope `user`
- `<workspace>/.cursor/mcp.json` → scope `project` (project wins name ties;
  workspaces come from Cursor `workspaceStorage`)

Commands, args, URLs, env values, and workspace paths never leave the
endpoint. Steady state emits nothing (checkpoint hash). This is
**intent-to-use** inventory; live MCP calls still come from the
`postToolUse` hook as `tool_calls[]` with `action_class=mcp_call`.

## Spool and flush

A **spool** (`~/.aim-collector-cursor/spool.jsonl`) buffers events;
`flush` (also called opportunistically by hook/scan runs) POSTs them to
the ingestion API `POST /v1/events` with a per-collector bearer token —
the same ingest protocol as the claude-code collector. Offline-safe:
events are appended to the spool before any network attempt, unacked
batches are kept, and a 50 MB drop-oldest cap guards disk.

## Commands

```
python -m cursor_collector install       # merge hook entries into ~/.cursor/hooks.json (idempotent)
python -m cursor_collector uninstall     # remove our hook entries (foreign entries preserved)
python -m cursor_collector hook <event>  # invoked BY Cursor (stdin JSON)
python -m cursor_collector watch         # daemon: scan state.vscdb, emit usage events, flush
python -m cursor_collector scan-once     # one scan pass (for scheduled-task deployments)
python -m cursor_collector flush         # drain spool to ingestion
```

## Configuration

Managed config file (dropped by Intune/SCCM, Jamf, or config-management), env
vars override it. Search order: `AIM_CONFIG_FILE` env →
`%ProgramData%\AI-Monitoring\collector\config.json` (Windows) /
`/Library/Application Support/AI-Monitoring/collector/config.json` then
`~/Library/Application Support/AI-Monitoring/collector/config.json` (macOS;
`/etc/aim-collector` is AIM-743 legacy only) /
`/etc/aim-collector/config.json` (Linux) → `<state dir>/config.json`.

Keys: `ingest_url`, `token_file` (preferred), `token` (dev only),
`hash_salt`, `device_id` (Intune device id, dropped by endpoint tooling —
see "Endpoint identity attestation (AIM-58)" in
`collectors/claude-code/README.md`).

| Var | Default | Purpose |
|---|---|---|
| `AIM_INGEST_URL` | (required for flush) | ingestion base URL |
| `AIM_COLLECTOR_TOKEN` | (required for flush) | per-collector bearer token |
| `AIM_HASH_SALT` | (config/fallback) | HMAC pseudonymization salt |
| `AIM_STATE_DIR` | `~/.aim-collector-cursor` | spool, checkpoint, salt fallback, config |
| `AIM_CONFIG_FILE` | (search order) | explicit config file path |
| `AIM_DEVICE_ID` | (auto-detect) | Intune/Entra device id override (dev/test) |
| `AIM_CURSOR_HOOKS_FILE` | `~/.cursor/hooks.json` | hooks file to manage (tests/dev) |
| `CURSOR_USER_DIR` | OS default | Cursor `User/` data dir (tests/dev) |
| `CURSOR_HOME` | `~/.cursor` | Cursor home dir (tests/dev) |
| `AIM_HOOK_COMMAND` | `sys.executable -m cursor_collector` | hook command prefix override |

The state dir deliberately differs from the claude-code collector's
(`~/.aim-collector`) so spool/checkpoint never interleave when both
collectors run on one machine.

## Packaging / deployment (handoff to AIM-28 / AIM-42)

- v1: Intune package wraps a pinned CPython embeddable distro + this
  source, or PyInstaller single binary per OS. Version-pinned; update path
  = new Intune package version (no self-update in v1 — smaller attack
  surface).
- WSL note: Cursor inside WSL is a *separate* endpoint from the Windows
  host. The collector must run inside WSL too (Linux binary + install
  step). Intune covers the Windows side; WSL rollout needs a bootstrap
  script or Ansible-like push.
- macOS: out of scope for pilot.

## Known limitations

- **Hook payload fragility**: field names/shapes in Cursor hook payloads
  vary by event and Cursor version and are not a stable API. The handler
  is defensive, but a Cursor update can silently reduce what we observe
  (e.g. lose `model`). Fleet monitoring should alert on sudden
  model/token observability drops.
- **`afterAgentResponse` / `stop` reliability**: these hooks are known to
  fire unreliably in cloud/background agents; usage volume derived from
  hooks alone will undercount there. The vscdb scan partially
  compensates.
- **state.vscdb is undocumented**: the `ItemTable` key/value format is a
  reverse-engineered, version-fragile surface. Parse failures are
  skip-and-continue by design; a format change degrades this path to a
  quiet no-op, not an error.
- **No per-request token counts from hooks**: hook payloads rarely carry
  token usage, so `tokens_*` and `cost_estimate_usd` are only populated
  when observable (mainly the vscdb path). Hook-only events are
  session/flags/identity signals.
- **Proxy ingestion remains the breadth fallback**: endpoint hooks give
  depth on managed devices; the proxy collector (`collectors/proxy/`)
  covers tools and devices without an installed collector.

## Tests

```
python3 -m unittest discover -s tests -v
```

Schema conformance of emitted events against the canonical AIM-18 schema,
using the same AJV setup as the ingest service:

```
node collectors/cursor/validate_schema.mjs   # from the repo root
```
