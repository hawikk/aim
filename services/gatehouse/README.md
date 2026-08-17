# gatehouse

PR-time security scanning — free **PR-security pillar** of the stack
([AIM-161](/AIM/issues/AIM-161)). **Not** a CI/CD product.

Runs Semgrep (SAST), Gitleaks (secrets), Checkov (IaC) and Trivy (deps) against
the lines a pull request changed, posts **one** check run and **one** comment,
and publishes every finding to the alert bus as `security.alert/v1.1`. IaC
findings map to CNAPP rule IDs (same family as post-deploy posture).

| Doc | Audience |
|---|---|
| [Product positioning](../../docs/product/gatehouse.md) | External / buyers — what it is, is not, install, comparison |
| [Stack overview](../../docs/product/stack-overview.md) | Pillar map, free vs commercial framing |
| [GitHub App design](../../docs/gatehouse-github-app.md) | Permissions, retention, threat model, AI reviewer |

## Run a scan without GitHub

```bash
docker compose build gatehouse
docker run --rm -v "$PWD":/repo:ro gatehouse:dev \
  scan --repo-dir /repo --repo-name owner/name --pr 0 --base origin/main
```

Add `--json` for the machine-readable form (findings, suppressions, the alerts
that would be published). Exit code is 1 when something blocks, 0 otherwise —
so it works as a plain CI step for repos that are not on GitHub.

## Tests

```bash
# Unit suite — no scanners needed, runs in the repo-wide python-tests job.
python -m pytest services/gatehouse -q

# Acceptance suite — needs the four scanners, so it runs in the image.
docker compose run --rm gatehouse-tests

# Bus round-trip against a real Redis (opt-in).
ALERT_BUS_TEST_URL=redis://127.0.0.1:6399/0 python -m pytest services/gatehouse -q
```

The acceptance suite auto-skips when the scanner binaries are absent, which is
the normal state of a laptop and of the hermetic CI job. It is **not**
skippable in the image.

## Layout

| Module | Responsibility |
|---|---|
| `server.py` | Webhook. HMAC verify, size cap, dispatch. |
| `github.py` | App JWT, repo-scoped installation tokens, checks + comments. |
| `workspace.py` | Ephemeral partial clone; deletes itself in a `finally`. |
| `diffscope.py` | Changed files and added line ranges, from the merge base. |
| `scanners/` | One adapter per tool, all normalizing to `models.Finding`. |
| `dedupe.py` | Stable identity + cross-scanner overlap collapse. |
| `suppress.py` | `.gatehouse.yml`, read from the base branch. |
| `bus.py` | `security.alert/v1.1` mapping + fail-closed publishing. |
| `checkrun.py` | Pure rendering of the check run and the one comment. |
| `cache.py` | Blob-SHA delta cache and the 30-day retention sweep. |
| `orchestrator.py` | The pipeline that wires the above together. |
| `aireview/` | AI/LLM security reviewer: bundle building, repo-graph, providers, validation ([AIM-162], [AIM-233]). |
| `suggest.py` / `fix_patch.py` / `catalogue/` | One-click suggested fixes on PR findings ([AIM-234]). |
| `eval/` | Eval harness + fixtures for the AI reviewer (stub or live endpoint). |
| `benchmark/` | Gate precision corpus + harness (AIM-334): per-gate FP/FN rates, FP budgets, auto-observe. |

## One-click suggested fixes (AIM-234)

For corroborated scanner findings with a reviewed catalogue patch, gatehouse
self-scans the fix and posts a committable GitHub ```suggestion (small) or a
sentinel draft-PR note (large, AIM-185 allowlist). Advisory only — never blocks.
Opt out per repo with `suggested_fixes.enabled: false` in `.gatehouse.yml`.

## AI reviewer (AIM-162 + AIM-233 repo-graph)

An optional second opinion over the same diff: added hunks plus ±20 lines of
context, plus a bounded call-graph of caller/callee *signatures* for symbols
the PR touched (AIM-233 / Greptile parity). Capped at 8 KB per file, 16 KB for
the graph slice, and 96 KB total. Sent to any OpenAI-compatible endpoint; the
response is validated, anchored to the diff, and merged into the same check
and comment. **Advisory by default** — AI findings never fail a check unless
the repo sets `ai_review.blocking: true` in `.gatehouse.yml`. Off entirely
unless a provider is configured. Self-hosted default; graph bodies never leave
the box — signatures only.

| Variable | Purpose |
|---|---|
| `GATEHOUSE_AI_PROVIDER` | `off` (default) / `http` / `stub` |
| `GATEHOUSE_AI_ENDPOINT` | default `http://127.0.0.1:11434/v1` (self-hosted friendly) |
| `GATEHOUSE_AI_MODEL` | required for `http` |
| `GATEHOUSE_AI_API_KEY` | optional bearer token; never logged |
| `GATEHOUSE_AI_MAX_BYTES` / `GATEHOUSE_AI_CONTEXT_LINES` | total / per-hunk caps |
| `GATEHOUSE_AI_GRAPH` / `GATEHOUSE_AI_MAX_GRAPH_BYTES` | enable graph (default on) / graph-slice cap (16 KB) |
| `GATEHOUSE_AI_PRICE_IN` / `GATEHOUSE_AI_PRICE_OUT` | USD per 1M tokens for the cost estimate |

```bash
# Eval: recall / clean-PR rate / cost per review, stub provider, no network.
python services/gatehouse/eval/run.py --markdown

# Against a live endpoint (GATEHOUSE_AI_MODEL required).
python services/gatehouse/eval/run.py --provider http --markdown
```

`gatehouse scan --no-ai` skips the reviewer even when configured; `--json`
includes `ai_stats` (tokens, estimated cost, drops) per run.

## Precision benchmark (AIM-334)

Every gate ships with a measured precision/recall on a versioned corpus
(≥50 seeded findings across secret/SAST/IaC/SCA + clean controls). CI runs the
harness inside the scanner image; a regression fails the acceptance job, and a
gate that exceeds its published FP budget auto-reverts to **observe** mode
(findings still report, do not block).

```bash
python services/gatehouse/benchmark/run.py --stats-only
python services/gatehouse/benchmark/run.py --require-scanners --markdown \
  --scorecard gate-precision-scorecard.json
```

See [`benchmark/README.md`](benchmark/README.md) and
[`docs/gate-precision-scorecard.md`](../../docs/gate-precision-scorecard.md).

[AIM-161]: /AIM/issues/AIM-161
[AIM-162]: /AIM/issues/AIM-162
[AIM-334]: /AIM/issues/AIM-334
[AIM-233]: /AIM/issues/AIM-233
[AIM-234]: /AIM/issues/AIM-234
