# Start: personal mode in one line

See which coding agents and MCP servers are on **this machine**, including
the ones nobody approved. No company, no SSO, no Docker, no database.

```bash
pipx install aimonitoring-security && aim personal
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787). That is the whole
path.

> Do **not** run `pipx install aim`. That PyPI name is AimStack's unrelated
> ML experiment tracker. Our distribution name is **`aimonitoring-security`**;
> the console script it installs is still **`aim`**.

Requires **Python 3.11+**. Runtime dependencies: none (stdlib only).

## What it does

`aim personal` scans local AI-tool state already on the disk: Claude Code
transcripts, Cursor `state.vscdb`, Kilo Code task logs, Kimi Code wire
logs, Grok Build usage logs, GitHub Copilot local sessions, and extracts
**metadata only** (tool, model, token counts, session/repo pseudonyms,
detector *names*). Prompt text, code, tool arguments, URLs, and env values
are never stored and never leave the box.

The dashboard binds **127.0.0.1 only**. Personal mode makes **zero outbound
network calls**. Verify by running it with networking off.

Events land in `~/.aim-collector/personal.db`. Single implicit local user;
no auth.

## Useful flags

```bash
aim --version                 # expect: aim 0.1.4  (matches PyPI)
aim personal --help
aim personal                  # scan once + serve the dashboard
aim personal --watch          # re-scan every 30s while open
aim personal --port 9000
aim personal --scan-only      # refresh the local store, no server
aim status                    # local, network-free: what's installed
```

## What this is not

Personal mode is not a fleet control plane and not an enforcement product.
It does not send telemetry to us, to PyPI, or to any ingest URL. To join a
company stack you would run `aim join` against *your* ingest. That is a
different command, and it is opt-in.

Community is free and uncapped (Apache-2.0, no DRM). Hosted Cloud and
Enterprise: [pricing](pricing.md).

Self-host the full dashboard with Docker:
[self-host demo](deployment/self-host-quickstart.md).

Trust / privacy (what is collected, retention, access control):
[trust](trust.md). MCP `name` + `scope`: [inventory](inventory.md).
