# Documentation

This repository is a curated public snapshot of a larger internal monorepo.
The documentation here is the subset that is useful if you are evaluating,
self-hosting, or contributing to AI Monitoring.

Some documents cross-reference internal design notes, rollout records, and
compliance material that are **not** published here. Those links will not
resolve, and that is deliberate rather than an oversight — the excluded
material is either specific to one deployment or contains operational data
from a private fleet.

## Start here

| Document | What it covers |
|---|---|
| [`architecture.md`](architecture.md) | How the collectors, ingest, control plane, and dashboard fit together |
| [`product/stack-overview.md`](product/stack-overview.md) | The product surface in one page |
| [`product/gatehouse.md`](product/gatehouse.md) | PR/CI security gating |
| [`deployment/self-host-quickstart.md`](deployment/self-host-quickstart.md) | Getting a stack up |

## Privacy and data handling

The metadata-only guarantee is the core design constraint, so it is worth
reading before anything else.

| Document | What it covers |
|---|---|
| [`privacy/data-minimization-and-pseudonymization.md`](privacy/data-minimization-and-pseudonymization.md) | What is collected, what is never collected, and how identities are pseudonymized |
| [`privacy/auditor-privacy-overview.md`](privacy/auditor-privacy-overview.md) | The same ground, framed for an auditor |
| [`security/adr-no-semantic-content-classifiers.md`](security/adr-no-semantic-content-classifiers.md) | Why detection is pattern-based rather than model-based |
| [`security/adr-independence-from-agent-loop.md`](security/adr-independence-from-agent-loop.md) | Why monitoring does not sit inside the agent loop |
| [`security/enforcement-capability-matrix.md`](security/enforcement-capability-matrix.md) | Which collectors can actually block, and which only observe |

## Deployment

| Document | What it covers |
|---|---|
| [`deployment/self-host-quickstart.md`](deployment/self-host-quickstart.md) | Compose-based install and first login |
| [`deployment/prebuilt-images.md`](deployment/prebuilt-images.md) | GHCR pull path instead of a source build |
| [`deployment/air-gapped-install.md`](deployment/air-gapped-install.md) | Installing with no outbound network |
| [`deployment/backup-restore.md`](deployment/backup-restore.md) | Backup and restore procedure |
| [`deployment/enrollment-and-heartbeat.md`](deployment/enrollment-and-heartbeat.md) | How devices enrol and stay healthy |
| [`deployment/os-install-enroll-matrix.md`](deployment/os-install-enroll-matrix.md) | Which install/enrol paths are proven per OS |

## Collectors and data contract

| Document | What it covers |
|---|---|
| [`adapter-contract.md`](adapter-contract.md) | Writing a collector for a new tool |
| [`collector-schema-versioning.md`](collector-schema-versioning.md) | How the event schema evolves |
| [`ingest-dlq-and-replay.md`](ingest-dlq-and-replay.md) | Rejected events, the DLQ, and replay |
| [`otel-genai-integration-guide.md`](otel-genai-integration-guide.md) | OpenTelemetry GenAI ingestion |
| [`tool-version-matrix.md`](tool-version-matrix.md) | Supported tool versions |
| [`app-llm-provider-catalogue.md`](app-llm-provider-catalogue.md) | Recognized providers and models |

## Platform internals

| Document | What it covers |
|---|---|
| [`identity-mapping-design.md`](identity-mapping-design.md) | Pseudonymous identity and reveal |
| [`guardrail-engine-v1.md`](guardrail-engine-v1.md) | Rule evaluation |
| [`guardrail-abac-conditions.md`](guardrail-abac-conditions.md) | Attribute-based rule conditions |
| [`api-read-path-pagination.md`](api-read-path-pagination.md) | Read API conventions |

## Frontend

| Document | What it covers |
|---|---|
| [`how-to-add-dashboard-view.md`](how-to-add-dashboard-view.md) | Adding a dashboard view |
| [`frontend-design-system.md`](frontend-design-system.md) | Design tokens and components |
| [`frontend-deep-links.md`](frontend-deep-links.md) | Deep-link routing |
