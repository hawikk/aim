# shadow-ai

Shadow AI discovery — **IdP OAuth / SaaS grant inventory** (Track 2)
plus tool-level risk inventory (foundation). Catalogue breadth expanded
(40 AI SaaS tools in `catalogue/ai-tools.json`).

Answers: **which employees authorized which AI SaaS apps with work identity**,
without a collector on that path.

## Signal sources

1. **IdP OAuth grants** (primary)
   - `fixture` — dogfood / CI (Google Reports shape **or** normalized inventory)
   - `google` — Google Workspace Admin SDK Reports API `token` activities
   - `entra` — Microsoft Graph `oauth2PermissionGrants` + servicePrincipals + users
   - `okta` — Okta Apps API + user assignments
   - `multi` — comma-separated combination via `SHADOW_AI_GRANT_SOURCES`
2. **Proxy domain observations** (corroborator) — read-only over stored proxy events.

## Outputs

| Table / API | Content |
| --- | --- |
| `shadow_ai_grants` | Per (pseudonym, idp, app) grant metadata |
| `shadow_ai_findings` | `unapproved_ai_saas_grant` rows |
| `shadow_ai_tools` | Aggregate tool inventory + risk |
| `shadow_ai_discovery_queue` | Uncatalogued IdP apps + draft catalogue entries |
| `GET /api/shadow-ai/grants` | Analyst list (pseudonyms) |
| `GET /api/shadow-ai/tools` | Tool inventory |
| `GET /api/shadow-ai/summary` | Headline counts + discovery lag (`discovery_queue_open`, oldest open age) |
| `GET /api/shadow-ai/discovery-queue` | Catalogue-ops queue; draft `proposed_entry` per candidate |
| `PATCH /api/shadow-ai/discovery-queue/:queueId` | Status transitions: open→proposed\|catalogued\|dismissed\|known_non_ai |

### Continuous catalogue ops

On every `shadow-ai sync`, active IdP grants that do **not** match a catalogue
tool and are not known-non-AI upsert into `shadow_ai_discovery_queue` with a
draft catalogue JSON fragment (`proposed_entry`) ready for PR review. Adding a
tool remains a data change to `catalogue/ai-tools.json`, never a code change.
| `GET /api/shadow-ai/summary` | Headline counts **incl. `grants_by_idp_source`** |
| `GET /v1/shadow-ai/summary` | Service-local summary (same per-IdP breakdown) |
| `POST /sync` | Sync stats include `grants_by_idp_source` |

## Production multi-IdP

Pilot every corporate IdP you have read-only access to:

```bash
export SHADOW_AI_GRANT_SOURCE=multi
export SHADOW_AI_GRANT_SOURCES=entra,okta,google
# Entra
export SHADOW_AI_ENTRA_TENANT_ID=...
export SHADOW_AI_ENTRA_CLIENT_ID=...
export SHADOW_AI_ENTRA_CLIENT_SECRET=...
# Okta
export SHADOW_AI_OKTA_ORG_URL=https://corp.okta.com
export SHADOW_AI_OKTA_API_TOKEN=...
# Google Workspace
export SHADOW_AI_GOOGLE_CREDENTIALS_FILE=/run/secrets/google-sa.json
export SHADOW_AI_GOOGLE_DELEGATED_ADMIN=admin@corp.example
# MUST match identity-sync so grant pseudonyms join event pseudonyms
export SHADOW_AI_PSEUDONYM_SECRET=$IDENTITY_SYNC_PSEUDONYM_SECRET

shadow-ai sync
# → grant_events_seen, grants_upserted, grants_by_idp_source: {entra, okta, google_workspace}
curl -s localhost:8090/v1/shadow-ai/summary | jq .grants_by_idp_source
```

Omit any child you do not have credentials for (`SHADOW_AI_GRANT_SOURCES=entra,okta`).

## Dev

```bash
cd services/shadow-ai
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
SHADOW_AI_GRANT_FIXTURE_PATH=fixtures/entra_grants.json .venv/bin/shadow-ai sync
SHADOW_AI_DATABASE_URL=sqlite:///./dev.db .venv/bin/shadow-ai inventory
```

## Privacy

Pseudonym only at rest. Same HMAC secret as identity-sync. Reveal is
identity-sync `POST /reveal` (audited). See
.

## Coding-tool auto-discovery

Uncatalogued signals that look like AI coding tools emit
`unknown_ai_coding_tool` findings (observe only). Heuristics:
`src/shadow_ai/coding_heuristics.py`. Analyst queue:
`GET /v1/shadow-ai/coding-discoveries`. Disposition via platform findings
status transitions.
