# Tool adapter runtime

**A new AI tool is configuration, not a code fork.**

| Path | Role |
|---|---|
| `manifests/*.yaml` | Per-tool adapter declarations |
| `schema/tool-adapter.manifest.schema.json` | Manifest contract |
| `aim_adapter/` | Runtime: discover → extract → emit |
| `aim_adapter/surfaces/` | Surface drivers (code only when surface type is new) |
| `../docs/adapter-contract.md` | Normative contract |

## Surfaces

| Type | Fidelity |
|---|---|
| `local_session_logs` | Depth (model/tokens when logged); formats: `jsonl_usage`, `json_session`, `sqlite_table` |
| `editor_extension_hooks` | Depth via legacy hooks; presence via extension id |
| `proxy_domain` | **Presence only** — domain hit, not prompts/tokens |
| `provider_api` | Depth for first-party OTel / provider export |

## Commands

```bash
cd collectors/adapter
python3 -m aim_adapter list
python3 -m aim_adapter proof
python3 -m pytest tests/ -q
```

## Add a tool (existing surface)

1. Copy an existing manifest, set `id` / domains / paths.
2. Keep `privacy.metadata_only: true`.
3. Run `python3 -m aim_adapter proof` (or unit tests).
4. No changes under `aim_adapter/surfaces/` required.

## Tools added through the contract

- **github_copilot** — adapter `proxy_domain` + extension inventory (presence);
  depth in `collectors/github-copilot` (metadata-only)
- **gemini_cli** — `local_session_logs` JSONL; config-only
- **codex_cli** — `local_session_logs` **`sqlite_table`** on `~/.codex/state_*.sqlite`; required the reusable SQLite format on the existing surface (not a new surface type)
- **windsurf** / **cline** (incl. Roo) / **amazon_q** — high-prevalence pack. Cline has depth via `json_session` + `records_key=taskHistory`; Windsurf and Amazon Q are presence-only after inspecting local state.
- **continue** / **cody** / **jetbrains_ai** — pack 2. Continue has depth via `sqlite_table` on `tokens_generated`; Cody and JetBrains AI are presence-only after inspecting local state.
- **tabnine** / **augment** / **supermaven** — pack 3. All three are presence-only after inspecting local state (Tabnine config/token, Augment chat/MCP, Supermaven binary cache). Residual: no metadata-only usage table.

See the manifests and `docs/adapter-contract.md` §4.
