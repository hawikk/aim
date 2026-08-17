# ADR — Independence from the agent execution loop

**Status:** Accepted  
**Date:** 2026-08-01  
**Owner:** Founding Engineer (mechanisms) · Security/CEO (policy residual)  
**Related:** AIM-639 · AIM-749 · AIM-750 · AIM-751 · AIM-752 · AIM-753 · AIM-502 scorecard Dimension 16 · AIM-456 failure-domain split

## Context

Competitive scorecard **Dimension 16 — Independence from the agent execution loop** scored **9 / Leader 7**. The architectural claim was already real:

- Endpoint collectors are **hooks and daemons outside the coding agent’s own process and telemetry**.
- The guardrail engine is a **separate service** over Postgres, not an in-agent plugin.
- The proxy / OS-egress path is **network-level** and does not share fate with any single IDE agent.

What 9 lacked was *proof that the agent cannot quietly disable the observer*:

1. An engineer’s agent can rewrite local `config.json` / `enforcement.json` if those files are user-writable and unsigned.
2. Killing the per-user collector process silences that process’s heartbeat unless a host-level signal remains.
3. There was no continuous attestation that the independence control plane still exists in the repo and deploy tree.

## Decision

We treat independence as a **control plane with cryptographic and process-domain separation**, not a documentation claim.

### D1 — Signed managed updates (tamper-evident)

Managed collector config and enforcement bundles ship as **Ed25519 signed envelopes** (`aim.signed-bundle/v1`). Endpoints hold only the **public** key (`/etc/aim-collector/config-pubkey.b64`). Ops signs offline / in CI with `scripts/sign_collector_bundle.py`.

In **harden mode** (`AIM_HARDEN=1` or `"harden": true`):

- Unsigned bundles are **refused**.
- Signature failures are **refused** and recorded as metadata-only `TamperEvent`s (`tamper-events.jsonl`).
- Callers retain last-known-good policy; the agent does not win by rewriting a file.

Bare unsigned JSON remains valid only for local development when harden is off.

### D2 — Anti-bypass suite

`collectors/integrity/tests/test_anti_bypass.py` simulates agent-local attacks:

| Attack | Expected control response |
|---|---|
| Flip `mode: enforce` → `shadow` inside a signed envelope | `invalid_signature` + High `policy_violation` alert |
| Drop a fresh unsigned policy file | `unsigned_in_harden` + alert |
| Point env config at evil unsigned file | refused under harden + alert |
| Forge envelope with garbage / agent-owned key | `invalid_signature` + alert |
| Kill user collector process | OOB host health remains independent |
| Spoof `key_id` with agent key | fleet public key rejects + alert |
| Unset `AIM_HARDEN` but leave `harden: true` in file | still refused + alert |
| Remove public key material | signed envelope fails closed + alert |
| Spoof user-local health file | does **not** satisfy OOB path (stale remains stale) |

Every detect path that yields a `TamperEvent` also produces a metadata-only
alert finding via `detect_and_alert` / `tamper_to_alert_finding` (AIM-750).

CI runs this suite on every PR (collector job).

### D3 — Out-of-band health signal

A **root-owned** systemd timer (`aim-collector-oob-health.timer`) writes `/var/lib/aim/oob-health.mtime` and may POST fleet heartbeat with `source: "oob_systemd"`. It does not run as the engineer’s user and is not a child of the coding agent. Staleness threshold mirrors fleet dead detection (3 × interval + slack).

This is independent of:

- the Claude Code / Cursor / Kilo / Kimi agent process,
- the per-user hook/watch daemon,
- GitHub Actions (endpoint host domain, not CI domain).

### D4 — Continuous independence attestation

`scripts/independence_attestation.py` emits `aim.independence.attestation/v1` JSON that must stay green. It checks artifact presence, sign/verify round-trip, harden refusal of unsigned config, observer package separation, root OOB unit shape / timer / script markers, install wiring, this ADR, and the continuous workflow itself.

Two CI paths (neither runs inside a coding-agent process):

| Path | When | Runner label | Why |
|---|---|---|---|
| PR gate (`ci.yml` python job) | every PR | `aim-ci` | blocks merge of regressions |
| Continuous job (`.github/workflows/independence-attestation.yml`) | cron every 6h + `main` path pushes + `workflow_dispatch` | **`aim-ops` only** | proves control plane on default branch even when no PR is open and when the PR pool is saturated |

The continuous job is deliberately **out-of-band relative to the PR agent loop**: it always evaluates `main` on schedule, never co-locates with `aim-ci`, and fails closed if OOB deploy units or the ADR disappear.

## Architecture (who observes whom)

```
┌─────────────────────────────────────────────────────────────┐
│  Coding agent process (Claude Code / Cursor / …)            │
│  — untrusted for security liveness                          │
└─────────────┬───────────────────────────────────────────────┘
              │ hooks (best-effort, can be attacked locally)
              ▼
┌─────────────────────────────────────────────────────────────┐
│  Endpoint collector (user or service account)               │
│  — signed config/enforce load (harden)                      │
│  — event spool + optional user heartbeat                    │
└─────────────┬───────────────────────────────────────────────┘
              │
              │  independent failure domain
              ▼
┌─────────────────────────────────────────────────────────────┐
│  OOB host health (root systemd timer)                       │
│  — /var/lib/aim/oob-health.mtime                            │
│  — device heartbeat source=oob_systemd                      │
└─────────────┬───────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────┐
│  Ingest + guardrail engine + proxy path (datacenter)        │
│  — not co-process with any coding agent                     │
└─────────────────────────────────────────────────────────────┘
```

## Non-claims (honest residual)

- We do **not** claim a determined admin/root attacker on the endpoint cannot disable monitoring. Harden mode assumes the public key and root units remain under MDM / config-management control (Intune / equivalent).
- We do **not** claim kernel-level integrity (IMA/EVM) in v1.
- Hook registration can still be user-tampered on unmanaged machines; fleet coverage + OOB staleness surfaces that as **dead/stale**, not as silent success.
- Content of prompts never leaves the endpoint (metadata-only); tamper events are metadata-only too.

## Consequences

| We gain | We accept |
|---|---|
| Provable refuse path for agent config rewrite | Ops must sign config/enforce pushes |
| CI-enforced anti-bypass + attestation | New Python dep: `cryptography` (integrity package / CI) |
| Host-level liveness independent of agent | Root timer install is part of Linux deploy path |
| Scorecard Dim 16 defensible at **10** when suite + ADR + OOB ship | Windows OOB parity is follow-up (Scheduled Task as SYSTEM) |

## Acceptance → score 10

Dimension 16 moves **9 → 10** when all of the following are true:

1. Signed-bundle + harden load path merged (`collectors/integrity`).
2. Anti-bypass suite green in CI.
3. This ADR checked in.
4. OOB health unit + script present under `deploy/linux/`, **and** `install.sh` enables the root timer + optional `AIM_CONFIG_PUBKEY_FILE` / `AIM_HARDEN`.
5. `python3 scripts/independence_attestation.py` exits 0.
6. Path-to-10 evidence: `docs/aim-639-independence-path-to-10.md`.
7. AIM-753 records the re-score with evidence links.

## Alternatives considered

| Option | Why not |
|---|---|
| HMAC with shared secret on endpoint | Agent that can read config can forge; asymmetric is required |
| Trust user-level heartbeat only | Agent can kill its own tree |
| eBPF / kernel observer as v1 | Out of pilot scope; MDM-managed signed config is enough for 10 |
| “Document architecture only” | Leaves Dim 16 at 9 — not provably unbypassable |

## References

- Implementation: `collectors/integrity/`
- Attestation: `scripts/independence_attestation.py`
- Sign tool: `scripts/sign_collector_bundle.py`
- Failure domains (CI plane): `docs/security/failure-domains.md`
- Enrollment/heartbeat: `docs/deployment/enrollment-and-heartbeat.md`
