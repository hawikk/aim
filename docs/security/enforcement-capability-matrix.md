# Enforcement capability matrix (per collector)

**Status:** live · **Scope:** what AI Monitoring can and cannot *block*.

This table exists because "guardrails" is a word that invites a reader to assume
more than the code does. Everything below is checkable against the collector
source in this repository.

## The one-sentence version

**Inline enforcement is not fleet-wide.** Exactly one collector — Claude Code —
can block anything, and it blocks only on the endpoint that produced the
prompt. Every other collector is observe-only, and the platform guardrail
engine never blocks at all.

## Matrix

| Collector | Capture surface | Can block locally? | Rails that can actuate |
| --- | --- | --- | --- |
| **Claude Code** (`collectors/claude-code`) | `UserPromptSubmit` + `PreToolUse` hooks (plus SessionStart/End, PostToolUse telemetry) | **Yes** | `secret-pattern-in-prompt` (block + break-glass confirm), `unapproved-mcp-server` (deny), `restricted-repo-access` (deny), `pii-in-prompt` (confirm challenge), `secret-in-tool-input` (redact via `updatedInput`) |
| **Cursor** (`collectors/cursor`) | `sessionStart/End`, `beforeSubmitPrompt`, `afterAgentResponse`, `postToolUse` hooks | **No** — observe only. The hook always exits 0 and has no stdout contract (`cursor_collector/hook.py`) | none |
| **Kilo Code** (`collectors/kilo-code`) | task / session-log watch — no hook API exists | **No** | none |
| **Kimi Code** (`collectors/kimi-code`) | log watch — no hook API exists | **No** | none |
| **GitHub Copilot** (`collectors/github-copilot`) | log watch — no hook API exists | **No** | none |
| **Grok Build** (`collectors/grok-build`) | usage-log watch — no hook API exists | **No** | none |
| **Generic adapter pack** (`collectors/adapter`) | session/log file readers | **No** | none |
| **Proxy** (`collectors/proxy`) | Squid/Zscaler log tailer — off-path by architecture | **No.** `export_blocklist.py` exports unapproved domains for **IT** to enforce on the corporate proxy under their own AUP authority; we enforce nothing | n/a (domain-level, someone else's control) |
| **OS egress** (`collectors/os-egress`) | process / connection inventory | **No** | none |
| **Platform guardrail engine** (`services/guardrail`) | post-ingest rule evaluation | **No** — `DECISION = "observe"` is hard-coded (`guardrail/engine.py`); every finding is detect-and-alert | none |

Structural proof of the split is in `collectors/parity-matrix.json`: only
`claude_code` lists `enforcement` among its surface `event_types`.

## What this means in practice

- A secret pasted into a **Claude Code** prompt on an endpoint with the managed
  bundle loaded is **blocked before it is sent**.
- The same secret pasted into **Cursor, Kilo Code, Kimi Code, Copilot or Grok
  Build** is **detected and alerted on, not blocked**. The prompt goes out.
- Nothing is blocked "in the network" by us. The proxy blocklist export is
  intelligence handed to IT; the enforcement is theirs.
- Coverage is per-endpoint, not per-tenant: a Claude Code host with no
  `enforcement.json` **fail-opens** to observe, deliberately — a policy
  distribution failure must not silently wedge an engineer's tooling.
  `GET /api/enforcement/coverage` and the `#/fleet` view report how many hosts
  can actually enforce today.

## Audit records

Endpoint decisions ride on the usage event as
`enforcement: {action, rule_id, policy_hash}`, with `action` ∈ `blocked` |
`would_block` | `confirmed` | `redacted` (schema v1.5/v1.6/v1.10). Coverage is
reported separately as `enforcement_posture`, so "zero blocks" is
distinguishable from "never evaluated". Metadata-only holds throughout: no
matched content, blocked payload, or reason string leaves the endpoint.

## Changing this table

Adding a blocking rail to another collector requires (a) a pre-send hook API
that tool actually exposes, (b) a security review of the rule's precision on a
representative corpus, and (c) an update to this table in the same pull request.
Do not describe a collector as enforcing before its `enforce.py` exists.
