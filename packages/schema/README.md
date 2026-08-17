# @aim/schema — Canonical AI Tool Usage Event, v1

This package is the single source of truth for what the AI Monitoring platform
collects. It contains:

- `schema/v1/ai-usage-event.schema.json` — the canonical JSON Schema
  (draft 2020-12) for the AI usage event.
- `VERSIONING.md` — compatibility policy (additive-only within major v1).
- `FIELDS.md` — field-by-field privacy justification (feeds the DPIA pack).
- `CANONICAL.md` — which schema is authoritative and which drafts were
  superseded (read this before touching anything here).
- `examples/` — valid example events (sanctioned tools + unapproved + otel +
  os-egress + enforcement) and content-rejection cases
  (`invalid-contains-prompt-text`, `invalid-response-body`,
  `invalid-message-content`, `invalid-tool-call-arguments`), exercised by
  `validate.py` and the no-content-egress harness.
- `validate.py` — validates every example against the canonical schema;
  exit 0 when all `valid-*` pass and all `invalid-*` are rejected.
- Continuous proof: `python3 scripts/no_content_egress.py --check`
  asserts closed objects, forbids content property names, injects every
  banned key into sample payloads, and runs the adapter emit strip harness.
  See `docs/security/no-content-egress.md`.

## security.alert/v1 — pick the right schema for your role

The cross-pillar alert contract (D3.1) ships in two forms. Which one
you validate against depends on whether you publish or consume, and getting it
wrong fails silently:

| You are a… | Validate against | Why |
|---|---|---|
| **publisher** (Cloud Sentry, AIM guardrail, PR scanner) | `schema/v1/security-alert.schema.json` | Strict. A typo'd field name is a publisher bug and must fail loudly at publish time, nearest the code that caused it. |
| **consumer** (inbox API, sentinel, UI) | `schema/v1/security-alert.consumer.schema.json` | The derived consumer profile (§6.1). Tolerates unknown fields and unknown open-vocabulary enum members, so an additive minor bump stays consumable. |

**A consumer that vendors the strict schema is the defect.** §6 makes
minor versions additive-only and §7.4 tells consumers to keep alerts carrying
unknown fields or enum members — but the strict schema rejects exactly those,
and §7.10 then drops them. The first minor bump silently empties the inbox,
and a dropped alert looks identical to no alert.

The profile is **derived, never forked**: `consumer_profile()` in `validate.py`
generates it (`python3 validate.py --write-consumer-profile`) and CI fails if
the committed file drifts, if the derivation relaxes anything outside the two
sanctioned axes, or if a new strict enum is left closed to consumers.

Two obligations the profile cannot enforce for you, because they live in the
consumer (D3.1 §2, §7.4):

1. **Project before you persist, render or log.** "Ignore unknown fields" means
   *drop* them. The profile accepts them so you do not lose the alert; an
   unknown field is constrained by no contract rule, so it is where prompt text
   or a secret would arrive. Project onto the fields you know first.
2. **Rank on `severity_id`, not the `severity` label.** A minor bump may add a
   label you do not know; the id is always 1–5. Ranking an unknown label as
   `medium` files a critical finding mid-inbox — burying a critical finding and
   dropping it are the same failure at different speeds.

`apps/api/src/alertbus.js` is the reference consumer for both.

## The one rule that matters most

**This schema is metadata-only.** It must never carry prompt text, response
text, code content, file contents, command output, or matched snippets from
detectors. `additionalProperties: false` means any attempt to attach content
fields fails validation at ingest by default. The ingest service's test suite
(`services/ingest/test/schema.test.ts`) proves content-bearing properties are
rejected and that validation errors never echo payload values.

## Running the tests

```sh
pip install -r ../../requirements-dev.txt   # provides jsonschema
pnpm --filter @aim/schema test              # == python3 validate.py
```

The same validator runs in CI both via `pnpm test` and in the Python test job.
