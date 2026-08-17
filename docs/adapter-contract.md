# Tool adapter contract

**Status:** ratified (implementation) · **Date:** 2026-07-29

**Companion code:** `collectors/adapter/`

## 1. Charter

We ship five hand-written collectors today (Claude Code, Cursor, Kilo Code, Kimi Code, Grok Build). The tool set grows every quarter (Copilot, Codex CLI, Gemini CLI, Windsurf, Aider, …). **Per-tool forks do not scale.** A new AI tool with an existing extraction surface type is a **manifest entry**. Only a genuinely new surface type requires code.

This document is the normative contract. The runtime in `collectors/adapter/` enforces it.

## 2. Tool adapter contract

Every tool adapter implements four concerns. Adapters are declared as YAML manifests under `collectors/adapter/manifests/` and validated against `collectors/adapter/schema/tool-adapter.manifest.schema.json`.

### 2.1 Discovery — is this tool installed / in use?

| Input | Output |
|---|---|
| Endpoint filesystem + optional process inventory + optional proxy/OS-egress observation | `DiscoveryResult` |

```text
DiscoveryResult {
  tool_id: string           # manifest id (e.g. github_copilot)
  present: bool             # installed or observed in use
  in_use: bool              # stronger signal: recent session/activity
  version: string | null    # when discoverable
  surface: surface_type     # which surface produced the signal
  evidence: string          # non-content: path class / domain / extension id
  error: Failure | null
}
```

Rules:

1. Discovery is **best-effort and fail-soft**. A missing path is `present=false`, not a crash.
2. Discovery never reads prompt/response content. Path existence, extension package.json version, and domain hit counts are enough.
3. `present` means “installed or ever observed”; `in_use` means activity within the discovery window (default: last 7 days of session mtime / domain hits).

### 2.2 Event extraction

Given a discovered tool and a surface, the adapter yields zero or more **metadata-only** `ai-usage-event` records conforming to `packages/schema/schema/v1/ai-usage-event.schema.json`.

```text
ExtractRequest {
  manifest: ToolManifest
  surface: surface_type
  source_records: []        # surface-specific (session files, hook payloads, proxy lines)
  identity: IdentityContext
}

ExtractResult {
  events: ai-usage-event[]
  dropped: int              # records rejected as contentful / unparseable
  failures: Failure[]
}
```

Rules:

1. **Metadata only.** Forbidden on the wire: `prompt*`, `response*`, `body`, `content`, `cmdline`, `args`, URL path/query, page title, file contents. The runtime strips these keys before emit; ingest still rejects via `additionalProperties: false`.
2. Emit exactly the fields you have. Never invent token counts or models.
3. First-class `tool` enum values (`claude_code`, `cursor`, `kilo_code`, `kimi_code`, `grok_build`, `genai_app`) are used when the schema already names the tool. Everything else is `tool: "other"` + `tool_raw: <manifest.id>`.
4. Session ids that are stable across days are re-hashed per UTC day (`HMAC(date || raw_id)`).

### 2.3 Field mapping → `security.alert/v1`

Adapters do **not** publish alerts directly. They emit `ai-usage-event` with `match_flags[]`. Downstream (guardrail / policy) maps flags onto `security.alert/v1` as follows:

| `ai-usage-event` field | `security.alert/v1` field | Notes |
|---|---|---|
| (platform) | `pillar` | always `ai_usage` for adapter-sourced findings |
| (adapter runtime) | `producer.name` | `aim-adapter` |
| `match_flags[].detector` | `finding_type` | e.g. `policy.unapproved_tool` (dots, not colons) |
| `match_flags[].severity` | `severity` | same vocabulary where possible |
| `tool` / `tool_raw` | `labels.tool` | display name for the tool |
| `host_ref` | `resource` / `subject_ref` (device) | pseudonymized; never raw hostname |
| `user_ref` | `subject_ref` (user) when present | null until identity mapping lands |
| `event_id` | `evidence.source_event_id` | pointer, not a copy of the event body |
| `ts` | `observed_at` | second-precision UTC |

Helper: `aim_adapter.alert_map.flags_to_alert_stubs(event)` produces the metadata-only stub used by publishers. Content never crosses this boundary.

### 2.4 Identity / device attribution

| Field | Derivation |
|---|---|
| `host_ref` | `HMAC-SHA256(hostname_or_device_id, company_salt)` → 64 hex |
| `user_ref` | `HMAC-SHA256(corporate_identity, company_salt)` when known; else `null` |
| `repo_ref` | `HMAC-SHA256(normalized_repo_or_workspace, company_salt)` when known; else `null` |

Salt resolution (same as existing collectors): `AIM_HASH_SALT` env → managed config → per-install random salt (dev only). Collectors never reverse a ref.

### 2.5 Failure semantics

| Condition | Behaviour |
|---|---|
| Manifest invalid vs schema | **Hard fail** at load time; adapter registry refuses the tool |
| Unknown `surface` type | **Hard fail** at load time — requires new surface code |
| Discovery path missing | Soft: `present=false`, no event |
| Unparseable session record | Soft: count in `dropped`, continue |
| Record contains forbidden content keys | Soft: strip keys; if nothing usable remains, drop |
| Schema validation failure on emit | Soft: refuse that event, increment failure counter; never partial-store content |
| Spool / network flush failure | Soft: leave event on local spool (existing spool-client contract); retry next tick |
| Surface-level exception | Soft: record `Failure{surface, code, message}` without stack traces that embed paths with user data when avoidable |

**Never:** crash the whole multi-tool agent because one tool’s log is corrupt.

## 3. Extraction surfaces

| Surface | What we observe | Fidelity | Honest limit |
|---|---|---|---|
| **`local_session_logs`** | On-disk session / task / wire logs (JSON, JSONL, SQLite-export) | **Depth:** model, tokens (when logged), session cadence, local match-flags | Requires readable local state; tool format changes need extractor updates if fields move. Content is scanned locally only. |
| **`editor_extension_hooks`** | IDE extension hooks / activity DB / extension presence | **Depth for hooks** (Claude Code PreToolUse etc.): enforcement + tool_use aggregates. **Presence for extension id alone.** | Hook depth needs a per-tool plugin that still implements this contract; mere extension discovery is inventory, not usage. |
| **`proxy_domain`** | Corporate proxy / SNI / OS-egress hostname hits matched to the domain catalogue | **Presence:** tool (or provider) was contacted; volume bytes when available | **Not depth.** No model, no tokens, no prompts. Domain observation cannot distinguish “Copilot chat” from “Copilot telemetry” beyond the catalogue rule’s category. |
| **`provider_api`** | Direct provider API instrumentation (OTel GenAI) or authenticated provider usage export | **Depth for first-party apps** (service name, model, tokens, latency) | Employee coding tools rarely expose this; reserved for `genai_app` / org-managed API keys. Requires provider or app cooperation. |

**Domain observation is presence, not depth.** That is intentional. Pair proxy/OS-egress breadth with endpoint hooks for sanctioned tools that need teeth.

### When is code required?

| Change | Code? |
|---|---|
| New tool on an existing surface (e.g. another CLI with JSONL sessions under `~/.tool/`) | **No** — add a manifest |
| New domain for an existing proxy-observed tool | **No** — catalogue / manifest domain list |
| New surface type (e.g. browser extension DOM, eBPF process args) | **Yes** — implement `surfaces/<name>.py` + register |
| Deeper extraction for a legacy hand-written collector (Claude hooks, Cursor vscdb) | Keep the legacy module; expose it behind the contract via `implementation: legacy` |

## 4. Two new tools added through the contract (no core changes)

| Tool | Why chosen | Primary surface | Secondary |
|---|---|---|---|
| **GitHub Copilot** | Already in `endpoints.json`; widely present on enterprise fleets; exercisable via proxy/OS-egress fixtures without a live IDE | `proxy_domain` | `editor_extension_hooks` (extension id inventory) |
| **Gemini CLI** | Google’s coding CLI with on-disk session state under `~/.gemini/`; same shape as other session-log tools; exercisable with fixtures | `local_session_logs` | `proxy_domain` (generativelanguage.googleapis.com) |

Both manifests live under `collectors/adapter/manifests/`. Neither required a change to surface implementations or the emit/identity core — only new YAML (+ fixture data for tests).

**Not chosen for the first pair:** Codex CLI was deferred (assumed JSONL; real state is SQLite). **Shipped** as `codex_cli` via the reusable `sqlite_table` format on `local_session_logs`.

**high-prevalence pack:** `windsurf`, `cline` (Cline + Roo), `amazon_q`. Named `tool=other` + `tool_raw`. Cline/Roo is the depth tool (`json_session` on inspected HistoryItem files; optional `records_key` for Cline `globalState.json`). Windsurf and Amazon Q stay presence-only (path / extension / binary / existing proxy catalogue) — their local stores are contentful (Cascade transcripts; Amazon Q CLI `data.sqlite3` history/conversations/auth).

**adapter pack 2:** `continue`, `cody`, `jetbrains_ai`. Continue is the depth tool (`sqlite_table` on inspected `~/.continue/dev_data/devdata.sqlite` `tokens_generated`). Cody and JetBrains AI stay presence-only after inspecting local state (VS Code `cody-local-chatHistory-v2` transcripts; JetBrains `ml-llm` chats). Optional glob on discovery paths names versioned JetBrains config trees.

**adapter pack 3:** `tabnine`, `augment`, `supermaven`. All three stay presence-only after inspecting local state (Tabnine `tabnine_config.json` / `.refresh_token_v2`; Augment chat + `mcpServers.json`; Supermaven `~/.supermaven` binary cache). Named `tool=other` + `tool_raw`. Existing proxy catalogue rule ids already join those `tool_raw` values.

## 5. Existing collectors on the contract

| Collector | Manifest | Surface(s) | Status |
|---|---|---|---|
| Claude Code | `claude_code.yaml` | `editor_extension_hooks` (+ legacy hook/transcript) | **On contract** via `implementation: legacy` → `collectors/claude-code` |
| Cursor | `cursor.yaml` | `local_session_logs` / `editor_extension_hooks` (vscdb) | **On contract** via legacy bridge |
| Kilo Code | `kilo_code.yaml` | `local_session_logs` | **On contract** via legacy bridge |
| Kimi Code | `kimi_code.yaml` | `local_session_logs` | **On contract** via legacy bridge |
| Grok Build | `grok_build.yaml` | `local_session_logs` (local run usage) | **On contract** via legacy bridge |
| Codex CLI | `codex_cli.yaml` | `local_session_logs` (`sqlite_table` on `state_*.sqlite`) | **On contract**; `other` + `tool_raw=codex_cli` |
| Proxy ingest | (catalogue, not a tool) | `proxy_domain` | Surface implementation reuses `endpoints.json` |
| OS egress | (catalogue-driven) | `proxy_domain` class signal | Companion to; not a per-tool fork |

**Documented reason some depth stays in legacy packages:** Claude Code’s PreToolUse/UserPromptSubmit enforcement and Cursor’s private vscdb layout are tool-specific parsers. Rewriting them as pure config would either lose fidelity or invent a second programming language inside YAML. The contract requires they **register as adapters** and **emit the same event / privacy boundary**; it does not require deleting working parsers on day one. New tools must not copy that pattern when a generic surface fits.

## 6. Config-not-code rule

```text
collectors/adapter/manifests/<tool_id>.yaml   ← add this for an existing surface
collectors/adapter/aim_adapter/surfaces/*.py  ← only when surface type is new
```

Proof: `python3 -m aim_adapter proof` (see `collectors/adapter/README.md`) loads manifests, extracts fixture events for Copilot + Gemini CLI, validates them against the schema, and prints fleet-style `by_tool` counts that include both tools — without touching core surface code.

## 7. Privacy boundary

Same as / existing collectors:

- Metadata only on the wire.
- `additionalProperties: false` at ingest.
- Forbidden-key strip in the adapter runtime.
- Pseudonymized `host_ref` / `user_ref` / `repo_ref`.
- Match flags store detector name + optional redacted fingerprint — never the matched secret text.

## 8. Residual risk

1. **Schema first-class enum growth** — new tools appear as `other`/`tool_raw` until Security promotes them (same path as kimi_code / grok_build). Fleet counts use `COALESCE(tool_raw, tool)` so they are still named.
2. **Legacy bridge lag** — deep collectors can drift from the manifest’s declared surfaces; CI proof covers generic surfaces + manifest load of legacy entries, not full re-run of every collector suite.
3. **Proxy fidelity ceiling** — Copilot via domain is presence; security wins that need prompt/secret depth still need an endpoint hook when available.
4. **Gemini CLI log format churn** — if Google changes session file shape, the manifest’s field map may need a minor update (still config if the surface stays `local_session_logs`).
