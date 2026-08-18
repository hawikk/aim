# copilot-collector — GitHub Copilot depth (AIM-1167)

Metadata-only usage collector for GitHub Copilot on the endpoint. Pure
Python 3 stdlib. Same enroll / spool / heartbeat contract as the other
collectors. `aim join` also writes official user hooks to
`~/.copilot/hooks/aim.json` so VS Code Copilot can refuse a prompt and
Copilot CLI can deny a tool call when `enforcement.json` is in enforce
mode.

## What it collects

- Tool identity: `tool=other`, `tool_raw=github_copilot` (not sanctioned)
- Extension / JetBrains plugin / CLI version when `package.json` or
  `plugin.xml` is readable
- Selected model from VS Code settings or session *metadata* keys
- Day-hashed session id + last-write timestamp
- Chat / agent / inline turn counts (`len(requests)` → `tool_use`)

## What it never collects

Prompt text, completions, chat bodies, file paths, code, OAuth tokens.
Chat session files on disk **do** contain those; the extractor allowlists
metadata keys and skip-lists content keys. Tests plant `LEAK_MARKER_*`
fixtures and fail if any marker reaches an event.

GitHub does **not** persist suggestion-accept or token counters locally.
This collector does not invent `tokens_in` / `tokens_out`. Org-level
adoption numbers belong on the Copilot Metrics API
([AIM-1168](/AIM/issues/AIM-1168)).

## Commands

```bash
python3 -m copilot_collector scan-once
python3 -m copilot_collector watch
python3 -m pytest collectors/github-copilot/tests -q
```
