# App-LLM provider / model catalogue

**Date:** 2026-08-01 · **Status:** shipped (catalogue v5)

## Ownership (clear)

| Surface | Path | Owner | Change path |
|---|---|---|---|
| **Domain catalogue (SoT)** | `collectors/proxy/endpoints.json` | **Engineering** (structure, domains, categories); **Security** (sanctioned flags, policy promotion) | PR; CI validates JSON + provider-api mirrors |
| **App-LLM provider set (mirror)** | `apps/api/src/routes/dashboard.js` → `PROVIDER_API_PROVIDERS` | Engineering | Must match `category: provider-api` providers; CI fails on drift |
| **New-source default providers (mirror)** | `services/guardrail/src/guardrail/new_sources.py` → `DEFAULT_PROVIDERS` | Engineering | Same membership as SoT; override via `APP_LLM_NEW_SOURCE_PROVIDERS` |
| **Model price catalogue (SoT for cost)** | `apps/api/src/pricing.js` → `PRICE_PER_MTOK` (+ personal-mode `collectors/claude-code/.../store.py`) | Engineering | PR; `pricing.test.js` fails when JS/Python tables diverge |
| **Runtime drift alerts** | `services/guardrail/src/guardrail/catalogue_drift.py` | Engineering (mechanism); Security triages Low alerts | Wired into evaluate-db new-sources |
| **Policy content** | `policies/guardrail/v1/core.yaml` approved_providers / approved_models | **Security** | Policy PR; not auto-expanded by catalogue ops |

**Rule:** never edit only a mirror. Change `endpoints.json` first (or `pricing.js` for models), update mirrors, run:

```bash
python3 scripts/check_provider_catalogue_drift.py --check
```

## Why

App-LLM metering only surfaces proxy events whose `provider` is in the
`provider-api` set. Competitive analysis called out first-party apps calling
Bedrock / Vertex as invisible, and hard-coded dashboard sets **drifted** from
`endpoints.json` (xAI already `provider-api` but missing from the view).

closes the residual:

1. **Completeness** — expand provider-api with Moonshot/Kimi, Together, Fireworks;
   repair merge corruption that left `endpoints.json` invalid JSON on main.
2. **Drift alerts** — CI mirror guard + runtime Low findings when a *new*
   uncatalogued provider string or unpriced model first appears.
3. **Ownership** — this document is the single ownership map.

## Catalogue v5 (`endpoints.json`)

| Provider id | Rule id(s) | Domains (suffix match) | Notes |
|---|---|---|---|
| `anthropic` | `anthropic-api` | `api.anthropic.com`, `api.claude.ai` | sanctioned path for Claude Code |
| `openai` | `openai-api` | `api.openai.com`, OpenAI azurefd front door | Azure resource hosts are **not** here |
| `azure_openai` | `azure-openai-api` | `openai.azure.com` | `{resource}.openai.azure.com` |
| `aws_bedrock` | `aws-bedrock` | regional `bedrock-runtime.*` + agent-runtime | distinct from Amazon Q (`aws` / `api`) |
| `google` | `google-gemini-api` | `generativelanguage.googleapis.com`, `aiplatform.googleapis.com` | Vertex + Gemini Developer API |
| `mistral` | `mistral-api` | `api.mistral.ai`, `codestral.mistral.ai` | |
| `cohere` | `cohere-api` | `api.cohere.ai`, `api.cohere.com` | |
| `groq` | `groq-api` | `api.groq.com` only | bare `groq.com` marketing excluded |
| `xai` | `xai-api` | `api.x.ai`, `api.xai.com` | |
| `openrouter` | `openrouter-gateway` | `openrouter.ai` | |
| `moonshot` | `kimi-moonshot` | Moonshot / Kimi API hosts | **Completeness** |
| `together` | `together-ai` | Together inference API | **Completeness** |
| `fireworks` | `fireworks-ai` | Fireworks inference API | **Completeness** |

Dashboard + guardrail mirrors: **13** providers (was 10; was 3 at phase-1).

### Deliberately not provider-api

| Rule | Category | Why |
|---|---|---|
| `google-gemini-web` | `web` | Consumer Gemini UI |
| `amazon-codewhisperer` | `api` | Amazon Q employee tool (`provider=aws`) |
| `deepseek` | `api` | Data-residency priority — server hits stay flagged |
| `huggingface` | `api` | Hub traffic too broad for clean App-LLM metering |

## Drift alerts (runtime)

After each guardrail evaluate-db pass:

| Rule id | Finding type | Severity | When |
|---|---|---|---|
| `app-llm-new-source` | `app_llm_new_source` | Medium | First-ever `(host_ref, known provider-api)` — |
| `app-llm-new-provider` | `app_llm_new_provider` | Low | First-ever **provider** string not in any endpoints.json rule |
| `app-llm-new-model` | `app_llm_new_model` | Low | First-ever **model** id not matching `PRICE_PER_MTOK` keys |

Runbook slug for both catalogue findings: `rb-app-llm-catalogue-drift`.

Env:

| Variable | Default | Meaning |
|---|---|---|
| `APP_LLM_NEW_SOURCE_LOOKBACK_HOURS` | 48 window |
| `APP_LLM_NEW_SOURCE_PROVIDERS` | (DEFAULT_PROVIDERS) | Override known provider-api set for new-sources |
| `APP_LLM_CATALOGUE_DRIFT_LOOKBACK_HOURS` | same as new-source window |

Edge-trigger: `UNIQUE (rule_id, event_id)` on the first event — re-runs never re-page.

### Operator response (catalogue drift)

1. **New provider** → decide: add `provider-api` rule (App-LLM metering), `api`/`web` rule (employee tool), or accept residual. Update `endpoints.json` + mirrors; open PR.
2. **New model** → add list price to `apps/api/src/pricing.js` **and** `collectors/claude-code/aim_collector/store.py`; confirm `pricing.test.js` green.
3. Do **not** treat Low catalogue findings as user incidents; they are ownership debt.

## Sync checklist (PRs that touch the catalogue)

1. Edit `collectors/proxy/endpoints.json` (valid JSON; bump `version` / `updated`).
2. If `category: provider-api` membership changed → update `PROVIDER_API_PROVIDERS` and `DEFAULT_PROVIDERS`.
3. Extend `collectors/proxy/tests/` fixtures/tests + `apps/api/test/app-llm.test.js` as needed.
4. `python3 scripts/check_provider_catalogue_drift.py --check`
5. Append a row to this doc.

## CI

- `scripts/check_provider_catalogue_drift.py --check` — static checks job
- `scripts/check_provider_catalogue_drift.py --self-test` — proves the guard fires
- Proxy unit tests load `endpoints.json` (invalid JSON fails the suite)
- `apps/api/test/pricing.test.js` — JS/Python price-table parity

## Residual gaps

- Regional Vertex / Bedrock hosts beyond the listed set → PR on observation.
- HuggingFace Inference-only promotion if dogfood shows first-party volume.
- Populating `subnets.json` remains a network-team prerequisite for reducing
  `traffic_class=unknown`; catalogue alone cannot reclass without CIDRs.
