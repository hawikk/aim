# Security stack overview (product)

Short map of the pillars for external readers and landing copy. Engineering
detail remains in [architecture.md](../architecture.md) and per-service READMEs.

## One stack, distinct pillars

AI Monitoring ships **security visibility and guardrails for AI coding tools**,
with a free **PR-security** pillar that shares the same alert bus as cloud
posture (CNAPP) findings. We do **not** sell a CI/CD platform.

```text
  Endpoints / AI tools          Pull requests              Cloud / IaC
  ─────────────────             ─────────────              ──────────
  collectors + proxy            Gatehouse (free)           CNAPP posture
  guardrail engine              one check + comment        (Cloud Sentry)
         │                              │                        │
         └──────────── security.alert/v1.1 bus ──────────────────┘
                              │
                         Sentinel / SIEM / inbox
```

| Pillar | Role | Product posture |
|---|---|---|
| **AI usage monitoring** | What tools, models, and policy hits appear on the fleet (metadata-only) | Core commercial product |
| **Guardrails** | Prompt/MCP/tool policy, secret/PII signals, enforcement modes | Core commercial product |
| **Gatehouse** | Diff-scoped Semgrep + Gitleaks + Checkov + Trivy → one PR check/comment; IaC maps to CNAPP rule IDs | **Free / OSS PR-security pillar** — [gatehouse.md](./gatehouse.md) |
| **CNAPP / Cloud Sentry** | Post-deploy cloud posture | Paired commercial pillar; same rule family as Gatehouse IaC map |
| **Hygiene** | Full-history secret/token hygiene (not PR-diff) | Supporting pillar |
| **Sentinel / alert bus** | Fan-out of `security.alert/v1.1` to Slack, webhooks, SIEM | Shared fabric |

## Gatehouse in one sentence

**Gatehouse is free PR security for this stack** — not a scanner brand war, not
an Actions runner product, not CI/CD-as-a-service. See
[gatehouse.md](./gatehouse.md).

## Language we use / avoid

| Prefer | Avoid |
|---|---|
| PR-security pillar, PR-time security review | CI/CD platform, CI/CD product |
| Diff-scoped scanners on pull requests | “Our CI mesh” / selling runner capacity |
| CNAPP-aware / same rule IDs pre-merge and post-deploy | “Replaces GHAS / Semgrep / Snyk” |
| One check, one comment, shared alert bus | Four competing vendor checks as the pitch |
| Free Gatehouse pillar of the stack | Paid “pipeline product” SKU |

## Related engineering docs

- AIM architecture (collectors, ingest, privacy): [architecture.md](../architecture.md)
