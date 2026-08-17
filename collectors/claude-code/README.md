# aim-collector — Claude Code endpoint collector (AIM-20)

Metadata-only usage collector for Claude Code on Windows / WSL / Linux.
Pure Python 3.9+ stdlib. No third-party dependencies — deliberate, so the
endpoint package stays trivially auditable and easy to ship via Intune.

## What it collects (and what it never collects)

Collects **metadata only**, per the locked content policy (AIM-16) and the
ratified event schema (`packages/schema/schema/v1/ai-usage-event.schema.json`,
AIM-18):

- model, token usage (`tokens_in`/`tokens_out`; cache-read folds into
  `tokens_in` in schema v1), pseudonymized repo/cwd/host refs
  (HMAC-SHA256), tool version, timestamps
- `session_id` re-hashed per UTC day — `HMAC(utc-date || raw_id)` — so a
  long-lived Claude Code session cannot be profiled across days (AIM-61)
- `match_flags` set by local secret/PII pattern matchers
- per-session tool-call aggregates as `event_type="tool_use"` events
  (schema v1.1, AIM-86 — see below)
- cost is computed platform-side from the price table — the collector does
  not send cost

It **never** transmits prompt text, tool input/output, file contents, or
transcript content. Secret/PII matching runs on the endpoint; only
detector names leave the machine. Ingest rejects out-of-schema fields
whole, so a content leak would fail closed, not land in storage.

Schema gaps raised on AIM-18 that remain open: no cache-token split
(cache_read still folds into `tokens_in`).

## Tool-call capture (AIM-86)

The transcript watcher also counts tool invocations and emits one
`event_type="tool_use"` event (schema v1.1) per session per scan when
there are new calls — independently of token deltas, so a scan with only
tool activity still produces an event.

What IS captured, per tool per flush window (`tool_calls[]`):

- tool name as Claude Code names it (`Bash`, `Edit`, `WebFetch`, ...)
- MCP server id for `mcp__<server>__<tool>` names (split into
  `mcp_server` + `tool_name`)
- `action_class`: `fs_read` / `fs_write` / `shell` / `network` /
  `mcp_call` / `other`
- invocation count (delta-emitted against the checkpoint, so dashboards
  can sum)
- `duration_ms` — currently always `null` (schema-valid): pairing
  tool_use blocks with their tool_result across incremental scans would
  need pending-call state in the checkpoint; not cleanly derivable

What is NOT captured, ever: tool arguments, command lines, file paths,
URLs, tool output, prompts. Only the tool_use block's `name` field is
read; `input` is never touched. The schema's
`additionalProperties: false` on tool_calls entries makes any attempt to
attach arguments fail validation at ingest, and `events.validate()`
rejects them locally first.

## MCP config inventory (AIM-97 / AIM-570)

On each transcript scan the collector also reads Claude Code MCP config
and emits one `event_type="inventory"` event (schema v1.2) when the
configured server set changes — name + scope only:

- `~/.claude.json` top-level `mcpServers` → scope `user`
- `~/.claude.json` `projects.<path>.mcpServers` → scope `project`
- `<project>/.mcp.json` → scope `project` (project wins name ties)

Commands, args, URLs, env values, and project paths never leave the
endpoint. Steady state emits nothing (checkpoint hash).

## How it works

Two collection paths, both feeding one local spool:

1. **Hooks** (`hook` subcommand) — registered in `~/.claude/settings.json`
   for `SessionStart`, `SessionEnd`, `PostToolUse`, `UserPromptSubmit`.
   Claude Code pipes a JSON event to stdin; the collector converts it to a
   v1 event. Tool inputs are scanned locally for secret/PII patterns and
   then discarded — only flags survive.
2. **Transcript watcher** (`watch` subcommand) — incrementally tails
   `~/.claude/projects/**/*.jsonl` and emits per-session token/model
   usage events (delta-emitted, so dashboards can sum). Resumable via a
   checkpoint file.

A **spool** (`~/.aim-collector/spool.jsonl`) buffers events; `flush` (also
called by hooks/watch after each batch) POSTs them to the ingestion API
`POST /v1/events` with a per-collector bearer token. Offline-safe: spool
survives reboots and failed flushes.

## Commands

```
python -m aim_collector install    # merge hook entries into ~/.claude/settings.json (idempotent)
python -m aim_collector uninstall  # remove our hook entries
python -m aim_collector hook       # invoked BY Claude Code (stdin JSON)
python -m aim_collector watch      # daemon: tail transcripts, emit usage events
python -m aim_collector flush      # drain spool to ingestion
```

## Configuration (env)

| Var | Default | Purpose |
|---|---|---|
| `AIM_INGEST_URL` | (required for flush) | ingestion base URL, e.g. `https://ingest.corp.example` |
| `AIM_COLLECTOR_TOKEN` | (required for flush) | per-collector bearer token |
| `AIM_STATE_DIR` | `~/.aim-collector` | spool, checkpoint, host-id, config |
| `AIM_DEVICE_ID` | (auto-detect) | Intune/Entra device id override (dev/test) |

## Endpoint identity attestation (AIM-58)

Every flush attests endpoint identity once per batch in the POST
`/v1/events` envelope (`collector: {device_id, os_user}` — never inside
event payloads). Ingest resolves it to `user_pseudonym`/`team` via
identity-sync (AIM-49). `device_id` resolution order: `AIM_DEVICE_ID` env →
`device_id` key in the managed config file (the pilot path — Intune/SCCM
drops it alongside `config.json` at install time) → `dsregcmd /status`
DeviceId on enrolled Windows hosts. `os_user` is the OS login name; on
WSL/Linux it is the only attested field and identity-sync falls back to its
os_user/heuristic rules (AIM-24 ADR-001). If neither is attestable the block
is omitted and events are stored unattributed.

## Packaging / deployment (handoff to AIM-28 / AIM-42)

- v1: Intune package wraps a pinned CPython embeddable distro + this
  source, or PyInstaller single binary per OS. Version-pinned; update path
  = new Intune package version (no self-update in v1 — smaller attack
  surface).
- WSL note: Claude Code inside WSL is a *separate* endpoint from the
  Windows host. The collector must run inside WSL too (Linux binary +
  install step). Intune covers the Windows side; WSL rollout needs a
  bootstrap script or Ansible-like push.
- macOS: out of scope for pilot.

## Tests

```
python3 -m unittest discover -s tests -v
```
