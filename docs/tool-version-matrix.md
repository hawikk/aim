# Tool-version compatibility matrix

Continuous CI proof that every supported coding-agent collector still:

1. **Discovers** a pinned tool version from a recorded fixture, and
2. **Emits** a schema-valid usage event carrying that `tool_version`.

This is the path-to-10 residual for *Continuous tool-version matrix CI* (coding-agent runtime telemetry).

## Source of truth

| Artifact | Role |
|---|---|
| `collectors/tool-version-matrix.json` | Pin list (tool × ≥2 versions) + discovery mode + fixture paths |
| `collectors/tool-version-fixtures/<tool>/<version>/` | Recorded discovery inputs (state file, extension dir, install.json, adapter type) |
| `scripts/check_tool_version_matrix.py` | CI guard (`--check`) + aliveness self-test (`--self-test`) |

## Tools covered

| Tool | Discovery mode | Fixture shape |
|---|---|---|
| `claude_code` | `state_file` | `tool_version` text file (same contract as hooks) |
| `cursor` | `state_file` | `tool_version` text file |
| `kilo_code` | `vscode_extension_dir` | `extensions/kilocode.kilo-code-<ver>/package.json` via `AIM_KILO_EXTENSION_DIR` |
| `kimi_code` | `kimi_install_json` | `updates/install.json` → `lastSuccess.version` via `AIM_KIMI_HOME` |
| `grok_build` | `adapter_compose` | `<adapter_type>/<collector __version__>` |

## CI

In the `python-tests` job:

```bash
python3 scripts/check_tool_version_matrix.py --check
python3 scripts/check_tool_version_matrix.py --self-test
```

`--check` fails the build on missing tools, under-pinned versions, missing fixtures, discovery mismatches, event emit failures, or schema violations.

`--self-test` mutates a synthetic matrix until each rule fires, the same aliveness convention the other matrix guards use.

## Refreshing pins

When a pilot host or package example shows a newer tool version:

1. Add a fixture under `collectors/tool-version-fixtures/<tool>/<version>/`.
2. Append a pin to `collectors/tool-version-matrix.json` (keep ≥2 pins; drop the oldest only if deliberately pruning).
3. Run `python3 scripts/check_tool_version_matrix.py --check` locally.
4. Land via PR — CI enforces the matrix.

## Explicit non-goals

- Downloading or installing real Cursor/Claude/Kilo binaries in CI (supply-chain + flakiness cost; fixtures are the regression surface).
- Vendor SKU catalogue purchases that name fewer tools than we already cover.
