# Enforcement capability matrix (per collector)

**Status:** live · **Scope:** what AI Monitoring can and cannot *block*.
**Companions:** [inline-enforcement-design-2026-07.md](../inline-enforcement-design-2026-07.md)
(the phased proposal) · [aim-440-enforcement-reconcile.md](../aim-440-enforcement-reconcile.md)
(policy vs delivery) · [gatehouse-enforcing-vs-advisory.md](./gatehouse-enforcing-vs-advisory.md)
(a different pillar — PR/CI gates, not AI-tool collectors).

## The one-sentence version

**Inline enforcement is not fleet-wide.** Claude Code, Cursor, GitHub Copilot
(VS Code agent), and Kimi Code can block a user prompt on the endpoint when a
managed `enforcement.json` is loaded and the matching rule is in enforce mode.
Copilot CLI and Grok Build can deny **tool calls** only (vendor contract).
Kilo Code has no third-party hook API and stays observe-only. The platform
guardrail engine never blocks at all.

## Matrix

| Collector | Capture surface | Can block locally? | Rails that can actuate |
| --- | --- | --- | --- |
| **Claude Code** (`collectors/claude-code`) | `UserPromptSubmit` + `PreToolUse` hooks (plus SessionStart/End, PostToolUse telemetry) | **Yes** | `secret-pattern-in-prompt` (block + break-glass confirm), `unapproved-mcp-server` (deny), `restricted-repo-access` (deny), `pii-in-prompt` (confirm challenge), `secret-in-tool-input` (redact via `updatedInput`) |
| **Cursor** (`collectors/cursor`) | `sessionStart/End`, `beforeSubmitPrompt`, `preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `afterAgentResponse`, `postToolUse` | **Yes** — Cursor hook JSON + exit **2**. Observe path: exit 0, no stdout. Fail-open on missing/broken policy. Contract: `beforeSubmitPrompt` → `{"continue": false, "user_message": "..."}`; `preToolUse` / `beforeShellExecution` / `beforeMCPExecution` → `{"permission": "deny", "user_message": "...", "agent_message": "..."}` (`cursor_collector/enforce_cursor.py`) | `secret-pattern-in-prompt` (`beforeSubmitPrompt`), `secret-in-tool-input` (`preToolUse`, `beforeShellExecution` — deny; bash restricted-repo is out of scope), `unapproved-mcp-server` (`beforeMCPExecution`) |
| **GitHub Copilot** (`collectors/github-copilot`) | Official user hooks in `~/.copilot/hooks/aim.json` (VS Code agent + Copilot CLI). Also scan of extension / CLI homes. | **Yes** — VS Code agent: `UserPromptSubmit` (`continue: false` + exit 2) and `PreToolUse` (`permissionDecision: deny` + exit 2). Copilot CLI: `preToolUse` denies; command-hook output on `userPromptSubmitted` is dropped by GitHub, so the CLI does **not** block the initial prompt. Fail-open on missing/broken policy. Shared mapper: `aim_collector/generic_hook.py`. | `secret-pattern-in-prompt` (VS Code agent), `secret-in-tool-input` (VS Code + CLI) |
| **Kimi Code** (`collectors/kimi-code`) | Official `[[hooks]]` in `~/.kimi-code/config.toml` plus wire-log watch | **Yes** — `UserPromptSubmit` and `PreToolUse` are blockable (exit 2 or `permissionDecision: deny`). Fail-open on error/timeout. | `secret-pattern-in-prompt`, `secret-in-tool-input` |
| **Grok Build** (`collectors/grok-build`) | Official `~/.grok/hooks/aim.json` plus usage-log watch | **Yes, tools only** — xAI documents `PreToolUse` as the only blocking event (`{"decision":"deny","reason":"..."}` + exit 2). `UserPromptSubmit` is observe-only. | `secret-in-tool-input` (`PreToolUse`) |
| **Kilo Code** (`collectors/kilo-code`) | task / session-log watch — no third-party hook API exists | **No** | none |
| **Generic adapter pack** (`collectors/adapter`) | session/log file readers (including Codex CLI extract) | **No** — Codex has a hook API (`~/.codex/hooks.json`) but it is not wired into `aim join` / the wheel | none |
| **Proxy** (`collectors/proxy`) | Squid/Zscaler log tailer — off-path by architecture | **No.** `export_blocklist.py` exports unapproved domains for **IT** to enforce on the corporate proxy under their own AUP authority; we enforce nothing | n/a (domain-level, someone else's control) |
| **OS egress** (`collectors/os-egress`) | process / connection inventory | **No** | none |
| **Platform guardrail engine** (`services/guardrail`) | post-ingest rule evaluation | **No** — `DECISION = "observe"` is hard-coded (`guardrail/engine.py`); every finding is detect-and-alert | none |

Structural proof of the split is in `collectors/parity-matrix.json`:
collectors that can actuate list `enforcement` among their surface
`event_types`. Kilo does not.

Existing Cursor / Copilot / Kimi / Grok hosts need **`aim join` again** so
the new hook events are written into the vendor settings file. Blocking
only fires when `enforcement.json` is `mode: enforce`.

## What this means in practice

- A secret pasted into a **Claude Code**, **Cursor**, **Kimi Code**, or
  **VS Code Copilot** prompt on an endpoint with the managed bundle loaded
  is **blocked before it is sent**.
- The same secret in a **Copilot CLI** prompt is **not** blocked (GitHub
  drops command-hook output on `userPromptSubmitted`). A secret in a Copilot
  CLI **tool call** is denied.
- A secret in a **Grok Build** prompt is **not** blocked. A secret in a
  Grok **tool call** is denied.
- The same secret pasted into **Kilo Code** is **detected and alerted on,
  not blocked**. Kilo has no third-party hook API. The prompt goes out.
- Nothing is blocked "in the network" by us. The proxy blocklist export is
  intelligence handed to IT; the enforcement is theirs.
- Coverage is per-endpoint, not per-tenant: a hooked host with no
  `enforcement.json` **fail-opens** to observe (by design — see the design
  doc §4). `GET /api/enforcement/coverage` and the `#/fleet` view report how
  many hosts can actually enforce today.

## Audit records

Endpoint decisions ride on the usage event as
`enforcement: {action, rule_id, policy_hash}`, with `action` ∈ `blocked` |
`would_block` | `confirmed` | `redacted` (schema v1.5/v1.6/v1.10). Coverage is
reported separately as `enforcement_posture`, so "zero blocks" is
distinguishable from "never evaluated". Metadata-only holds throughout: no
matched content, blocked payload, or reason string leaves the endpoint.

## Changing this table

Adding a blocking rail to another collector requires (a) a pre-send hook API
that tool actually exposes, (b) Security sign-off per
[block-mode-precision-gates.md](./block-mode-precision-gates.md), and (c) an
update to this table in the same PR. Do not describe a collector as enforcing
before its enforce module exists (`enforce.py` / `enforce_cursor.py` /
`generic_hook.py`) and tests prove the rail.
