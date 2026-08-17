# ADR — No semantic content classifiers (metadata-only detection)

**Status:** Accepted  
**Date:** 2026-08-01  
**Owner:** engineering (mechanisms) · Security (revisit)
competitive review §9 · privacy posture

## Context

Market leaders (NeuralTrust, Noma, Harmonic, Lasso, Prompt) score **9/10** on detection depth largely by running **model/semantic classifiers on full prompt and response content**. Our scorecard is **7/10** on the regex/metadata plane (baseline 100% / evasion 94% / FP guards 100%). Closing the remaining gap to a commercial 9 **by shipping prompts off the endpoint** would reverse the privacy and works-council design that makes this product deployable in our environment.

## Decision

**We will not ship semantic content classifiers that require prompt/response text to leave the endpoint** (or to be stored/sent to a remote model for classification).

Detection remains:

1. **Endpoint matchers** — high-precision regex + validated detectors + multi-pass normalize/decode (this repo’s unified ruleset).
2. **Metadata-only telemetry** — detector names, fingerprints, counts; no prompt bodies in the pipeline.
3. **Adversarial corpus + CI floors** — rates are measured and non-regressed (floors: baseline 100 / evasion ≥90 / FP 100).

## Consequences

| We gain | We accept |
|---|---|
| Works-council / EU-friendly posture | Lower scorecard vs content-inspection vendors on “detection depth” |
| No third-party model dependency for core detect | Some class of intent/semantic abuse stays out of scope |
| Deterministic, auditable rules | Continuous investment in regex/evasion corpus, not LLM judge as product |

## When this would be revisited

Reopen this ADR only if **all** of the following hold:

1. Explicit Security/Legal decision that content inspection is in scope for a named use case.
2. DPIA / works-council path for that use case (lineage).
3. Technical design that still prefers **on-endpoint** models (no raw prompt egress) if feasible; remote classifiers require a separate product decision.

Until then, competitive pressure alone is **not** a reason to ship prompt-shipping classifiers. Research §9 “Do not chase” on stands.

## Alternatives considered

| Option | Why not (now) |
|---|---|
| Remote LLM judge on full prompts | Violates metadata-only; data residency + works-council |
| On-endpoint small model classifiers | Possible future; still needs policy + eval harness; not required for pilot security win |
| Buy NeuralTrust/Noma for semantic depth | Different product category (gateway); only if app-LLM **enforcement** is in scope |

## References

- `docs/security/detector-evasion-capability.md` (generated rates)
- `docs/security/block-mode-precision-gates.md`
- Competitive research: document `competitive-review` §6.5 / §9
