# kimi-collector — Kimi Code endpoint collector

Metadata-only usage collector for [Kimi Code](https://www.kimi.com/) (the
terminal CLI by Moonshot AI) on Linux / macOS / WSL. Pure Python 3 stdlib —
no third-party dependencies, same as the Claude Code and Kilo Code
collectors, so the endpoint package stays trivially auditable. Built as a
self-monitoring POC: it scans the local machine's real Kimi Code session
data under `~/.kimi-code/`.

## What it collects (and what it never collects)

Collects **metadata only**, per the locked content policy and the
ratified event schema (`packages/schema/schema/v1/ai-usage-event.schema.json`):

- model + provider (the wire log records both per request), token usage
  (`tokens_in`/`tokens_out`; all input-side counts — `inputOther`,
  `inputCacheRead`, `inputCacheCreation` — fold into `tokens_in` per v1,
  same rule as the Kilo collector folding cache-reads into input),
  pseudonymized host/workspace refs (HMAC-SHA256), tool version, timestamps
- one event per settled LLM API call (`usage.record`), delta-emitted, so
  dashboards can sum

It **never** transmits prompt text, response text, session titles, or file
contents. Kimi Code's `state.json` (`title`, `lastPrompt`) and `wire.jsonl`
(`turn.prompt`, `context.append_message`, `context.append_loop_event`)
contain all of these; the collector reads only the safe fields listed below
and never emits content. Local content scanning runs ON THE
ENDPOINT with the unified secret/PII matcher ruleset shared by all
collectors (canonical source `collectors/matcher-ruleset/matchers.py`): each `turn.prompt`'s text is
scanned in memory and discarded, and only detector names leave the machine
via `match_flags` on that turn's events. All other content-bearing records
are still skipped by record type. Ingest rejects out-of-schema fields
whole, so a content leak would fail closed.

`cost_estimate_usd` is **not** emitted: the Kimi Code wire log has no
provider-reported cost (unlike Kilo Code), and a local price table would
drift. Cost attribution belongs platform-side.

## How it works

Kimi Code has no hook/callback API for third parties, so the collector
**polls the CLI's on-disk session data**:

```
~/.kimi-code/
    session_index.jsonl                  # {sessionId, sessionDir, workDir} per line
    sessions/<wd_dir>/session_<uuid>/
        state.json                       # metadata; title/lastPrompt are content
        agents/<agent>/wire.jsonl        # protocol wire log (content; local scan)
    updates/install.json                 # lastSuccess.version -> tool_version
```

Session discovery: `session_index.jsonl` first (safe metadata), filesystem
walk of `sessions/` as fallback (workDir recovered from the safe `workDir`
key of `state.json`). Override the home dir with `AIM_KIMI_HOME`
(tests/dev/relocated installs).

The wire log is JSONL. Telemetry lives in two record types:

- `llm.request` — one per LLM API call: `time` (epoch ms), `model`,
  `modelAlias`, `provider`, `turnStep`, `kind`. Retries repeat the record
  with an extra `attempt` field.
- `usage.record` — token accounting per call, appended in the same order as
  the requests it settles: `usage = {inputOther, inputCacheRead,
  inputCacheCreation, output}`, plus `model` (the alias), `time`,
  `usageScope` ("turn").

Events pair each `usage.record` positionally with the most recent
`llm.request` for model/provider; `turnStep` is used only for that local
correlation (the schema has no field for it). Scanning is incremental via a
**byte-offset checkpoint per wire file**; a trailing partial line (writer
mid-append) is left for the next pass, and a shrunk file (rotation) resets
the offset. In-flight requests (request seen, usage not yet appended) are
held in the checkpoint's `pending` fragment and emitted when their
`usage.record` lands. The current turn's matcher flags are held in the
checkpoint's `turn_flags` fragment (detector names only) so a prompt
scanned in one pass still flags usage records that settle in a later pass;
a new `turn.prompt` replaces them.

Session ids: Kimi session ids are long-lived, so per the schema's
`session_id` rule they are re-hashed per UTC day — `HMAC(utc-date ||
sessionId)` — and cannot be profiled across days.

Provider: taken from the wire log's own `provider` field when present
(Kimi Code self-reports `"kimi"`), falling back to model-name prefix
derivation (`kimi`/`moonshot`/`k2`/`k3` → `"kimi"`; we emit `"kimi"`, not
`"moonshot"`, to stay consistent with the tool's self-reporting).

## Tool-call capture & MCP inventory

Mirrors the Claude Code collector's, against schema v1.2.

**Tool calls.** `context.append_loop_event` records nesting a
`tool.call` event are counted per wire file and delta-emitted as one
`event_type="tool_use"` event per scan when new calls appear —
independently of usage records, so a scan with only tool activity still
produces an event. What IS captured, per tool per scan window
(`tool_calls[]`):

- tool name as Kimi Code names it (`Bash`, `Edit`, `WebSearch`, ...)
- MCP server id for `mcp__<server>__<tool>` names (split into
  `mcp_server` + `tool_name`; same convention as the other collectors —
  no MCP tool has been observed in real Kimi wire data yet)
- `action_class`: `fs_read` / `fs_write` / `shell` / `network` /
  `mcp_call` / `other` (unknown tools are `other`, never a guess)
- invocation count (delta-emitted against the checkpoint's
  `tool_calls` / `emitted_tool_calls` fragments, so dashboards can sum;
  earlier checkpoints are backfilled via `setdefault`)
- `duration_ms` — always `null` (schema-valid): `tool.result` records
  carry no timing fields, so wall time is not derivable

What is NOT captured, ever: tool arguments, command lines, file paths,
URLs, tool output, `description`/`display` payloads. Only the
`tool.call` event's `name` field is read; `args` and every
`tool.result` payload are never touched. The schema's
`additionalProperties: false` on `tool_calls` entries makes any attempt
to attach arguments fail validation at ingest, and `events.validate()`
rejects them locally first.

**MCP inventory.** On each scan the collector reads the `mcpServers`
table of `~/.kimi-code/config.toml` (the section name the shipped CLI
parses; `mcp_servers` / `mcp.servers` spellings are accepted
defensively) and emits one `event_type="inventory"` event — but ONLY
when the configured server set changes (the checkpoint stores a hash of
the sorted names). Entries carry `name` + `scope` (`"user"`; config.toml
is the user-level config) and nothing else: commands, args, URLs, and
env values are never read into events or the checkpoint (env may hold
secrets). An empty list is a valid, explicit "no servers configured"
statement. `model`/`provider` are null, tokens are omitted, and the
session id is synthetic (`inv_<utc-date>_<host_ref[:12]>`) since no tool
session sits behind a config observation. On Python < 3.11 (no stdlib
`tomllib`) inventory is skipped quietly; usage collection is unaffected.

## Commands

```
python -m kimi_collector scan-once            # one pass; cron/systemd deployments
python -m kimi_collector scan-once --dry-run  # print events to stdout; no spool,
                                              # checkpoint, or flush (local verification)
python -m kimi_collector watch                # daemon: poll every N seconds (default 60)
python -m kimi_collector flush                # drain local spool to ingestion API
```

Spool/flush semantics, managed config file, and env vars (`AIM_INGEST_URL`,
`AIM_COLLECTOR_TOKEN`, `AIM_STATE_DIR`, `AIM_CONFIG_FILE`, `AIM_HASH_SALT`)
are identical to the Claude Code / Kilo Code collectors — see
`collectors/kilo-code/README.md`. Deployment: Linux cron/systemd user timer
or Windows scheduled task running `scan-once`.

## Gap report

Local telemetry is **sufficient for the v1 event contract**, with three
caveats:

1. **Request/usage pairing is positional.** `usage.record` carries no
   request id or `turnStep`; pairing assumes usage records land in request
   order (verified on real data: ~90%+ of requests are immediately followed
   by their usage record, the remainder are tool-call records interleaved
   between them — still order-preserving). A usage record with no pending
   request falls back to its own `model` field.
2. **`usageScope` is `"turn"` in current builds** — if a future build
   aggregates multiple calls into one usage record, events would aggregate
   the same way (still sum-correct for tokens).
3. **No cost.** No provider-reported cost on disk (see above), so
   `cost_estimate_usd` is never emitted. `match_flags` ARE emitted:
   `turn.prompt` text is scanned locally with the shared matcher ruleset and
   only detector names are attached to the turn's events, giving Kimi Code
   the same endpoint detection coverage as the other collectors.

Everything else the schema asks for (tokens, model/provider, session,
repo, tool version) is available from local telemetry. Verified against the
real `~/.kimi-code` data on the dev machine via `scan-once --dry-run` plus
canonical-schema validation of the emitted events.

## Tests

```
python3 -m pytest collectors/kimi-code/tests -q
```
