# MCP / agent inventory

The public claim is inventory, not enforcement: **which coding agents and
MCP servers are configured, including the ones nobody approved.**

AIM records that as metadata. It does not proxy MCP, does not read tool
arguments, and does not sit on the network path.

## What a row is

Collectors emit `event_type=inventory` with `configured_mcp_servers[]`
when the set of servers in a tool's config files **changes** (not on every
scan). Each entry is exactly:

| Field | Meaning |
| --- | --- |
| `name` | The server identifier as the user named it in the tool config (e.g. `github` in `mcp__github__*`). Cleartext on purpose: it names infrastructure, and policy matches it against an allowlist. Max 128 characters. |
| `scope` | `user` = tool-global / user-level config file. `project` = a project or workspace-level config file. |

That is the whole object. `additionalProperties: false`: if a collector
tries to attach a command, args, URL, or env value, ingest **rejects** the
event.

Live calls are a different event (`event_type=tool_use`) with
`tool_calls[]`: `tool_name`, optional `mcp_server`, `action_class`,
`count`, `duration_ms`. Still names and counts, never arguments or
results.

## Approved vs unapproved

Policy-as-code (`approved_mcp_servers`) is the allowlist.

| Allowlist | What you see |
| --- | --- |
| Empty (default) | **Discovery mode.** Every configured server and every MCP call is treated as unapproved and fires an *observe* finding. The point is to inventory the fleet before anyone locks a list. |
| Non-empty | Servers on the list are approved. Anything else is unapproved. |

Unapproved is a **status**, not a block. The platform engine does not deny
MCP calls. A few endpoint collectors can deny an unapproved server locally
when a managed `enforcement.json` is in `mode: enforce` and the vendor
hook exists. See the
[enforcement capability matrix](security/enforcement-capability-matrix.md).
Empty allowlist + enforce is not a thing you should turn on.

Analysts see the catalogue on the MCP servers view (`GET /api/mcp-servers`):
status (approved / unapproved), sources (configured / discovered), tool
names, call counts. Drill-down is role-gated.

## What this is not

- Not an inline MCP gateway. AIM does not mediate, rewrite, or inspect
  arguments.
- Not a prompt/tool-arg collector. There is no "show me the call" path.
- Not complete for every vendor. Grok Build currently has no local MCP
  config surface and no structured tool-call log, so
  `configured_mcp_servers[]` / `tool_calls[]` stay unsupported there until
  a metadata-only surface exists. That is a residual, not a hidden parser.

If you run a tool or MCP server AIM does not list, open an
[inventory-gap issue](https://github.com/hawikk/aim/issues/new?template=inventory-gap.yml)
on the public repo. Do not paste prompts, args, URLs, or env.
