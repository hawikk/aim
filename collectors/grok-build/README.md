# grok-collector — Grok Build / Paperclip endpoint collector

Metadata-only usage collector for **Grok Build** when it runs as a Paperclip
`grok_local` agent adapter (xAI-backed). Pure Python 3 stdlib — same packaging
posture as the Claude Code / Kimi Code collectors.

## What it collects (and what it never collects)

Collects **metadata only**, per the locked content policy and schema
v1.8 (`packages/schema/schema/v1/ai-usage-event.schema.json`):

- `tool = grok_build`, `provider = xai` (or derived from model prefix)
- model id (from env / CLI; default `grok-4.5` for this fleet's adapter)
- `cost_estimate_usd`: cache-aware xAI short-context list price
  (`uncached×$2 + cached×$0.30 + output×$6` per 1M for grok-4.5). Volume
  fields still use full `prompt_tokens`.
- daily-rehashed session id derived from `PAPERCLIP_RUN_ID`
- pseudonymized `host_ref` / optional `repo_ref` (workspace path HMAC)
- token counts from the local Grok usage log
  `~/.grok/logs/unified.jsonl` lines `shell.turn.inference_done`
  (numeric counters only — never prompt/response content):
  1. **Primary:** `scan-once` / `aim watch` tails the log and
     emits per-session token *deltas* for every local Grok turn, not only
     Paperclip heartbeats. First sight starts at EOF (no historical dump);
     set `AIM_GROK_LOG_BACKFILL_BYTES` for a one-shot catch-up window.
  2. Optional per-run resolve (`AIM_GROK_RUN_TOKEN_RESOLVE=1`) or explicit
     CLI `--tokens-in/--tokens-out` / env `AIM_GROK_TOKENS_IN/OUT` — disabled
     by default so continuous tail + run resolve cannot double-count.
- tool_version shaped as `paperclip-grok_local/<collector-version>`

It **never** transmits prompt text, response text, tool arguments, skill
contents, issue bodies, or file contents. It never opens Grok
`chat_history.jsonl` / prompt files — only run/identity env vars and the
metadata-only usage counters above.

## Why this exists

Grok Build on Paperclip was in active use and
invisible to AIM. Existing collectors covered Claude Code, Cursor, Kilo Code,
and Kimi Code; proxy endpoint intelligence had no xAI domains. This package
closes the endpoint path; `collectors/proxy/endpoints.json` closes the network
path.

## Commands

```
python -m grok_collector install --ingest-url URL --enroll-token TOKEN
python -m grok_collector emit-run --dry-run          # print one event for current run
python -m grok_collector emit-run                    # spool + flush
python -m grok_collector scan-once                   # emit if PAPERCLIP_RUN_ID present
python -m grok_collector heartbeat
python -m grok_collector flush
```

Spool/flush, managed config, and env vars (`AIM_INGEST_URL`,
`AIM_COLLECTOR_TOKEN`, `AIM_STATE_DIR`, `AIM_CONFIG_FILE`, `AIM_HASH_SALT`)
match the other endpoint collectors.

## Policy note

`grok_build` is a **first-class schema tool** (reportable by name). It is
**not** automatically added to `approved_tools` — that remains a Security
decision. Until approved, dashboard activity scoring and the unapproved-tool
guardrail still treat it as outside the allowlist (same posture as
`kimi_code`). See `docs/aim-271-grok-build-coverage.md`.

## Tests

```
python3 -m pytest collectors/grok-build/tests -q
```
