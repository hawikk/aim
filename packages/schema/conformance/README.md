# `security.alert/v1` — consumer conformance corpus

Every consumer of the alert bus replays this corpus in one test. It converts
D3.1 §7 ("what a consumer must never assume") from prose into CI, and it is an
acceptance criterion on the inbox and the
sentinel.

## Files

| File | What it is |
|---|---|
| `security-alert-v1.ndjson` | 23 entries, replayed **verbatim** — exactly the bytes a consumer would read off `secstack:alerts:v1`. One line is deliberately not JSON at all. |
| `security-alert-v1.manifest.json` | Expectations, keyed by 1-based line number. Kept out of the entries because a malformed line cannot carry its own metadata. |

## Manifest fields

`validity` — which schema profile accepts the entry:

| Value | Meaning |
|---|---|
| `publisher-valid` | Accepted by the strict publisher schema and by the consumer profile. |
| `consumer-only` | **Rejected by the strict schema, kept by the consumer profile.** Forward compatibility: a future minor version's new enum value or new optional field. |
| `invalid` | Rejected by both. A publisher bug or an attack. |
| `unparseable` | Not a JSON object. Must be counted and skipped, never fatal. |

`disposition` — what the consumer must *do*, which is the half only the
consumer can assert:

| Value | The consumer must |
|---|---|
| `accept` | Ingest normally. |
| `accept-idempotent` | Recognise the redelivery and not duplicate the row or the notification (§7.2). |
| `accept-separate` | Keep two records — `dedupe_key` is unique only *within* a pillar (§3.1.1). |
| `accept-degraded` | Ingest with the unknown value degraded per §7.4, never drop. For an unknown `severity`, degrade the *label* only — rank and threshold on `severity_id`, which is required and always in range. |
| `accept-escaped` | Ingest, and render as text — never as markup (§7.9). |
| `accept-delimited` | Ingest, and if it reaches a model, delimit it as data rather than instruction (§7.9). |
| `accept-flagged` | Ingest, and count a contract violation the schema cannot express (§3.2, §3.4). |
| `reject` | Drop, increment a counter, log the `alert_id` — and keep consuming (§7.10). |

## What `validate.py` already checks

`python3 packages/schema/validate.py` asserts the `validity` half: that each
entry parses (or does not), and that the declared profile accepts it. It also
asserts every `accept-flagged` entry really does violate a cross-field
invariant — otherwise the invariant checker would be tested only against clean
input and would prove nothing.

## What your consumer test must add

The `disposition` half. Replay the NDJSON through your real ingest path and
assert the observed behaviour, not the parse result:

```python
raw = (CONFORMANCE / "security-alert-v1.ndjson").read_text().splitlines()
manifest = json.loads((CONFORMANCE / "security-alert-v1.manifest.json").read_text())["entries"]
for line, entry in zip(raw, manifest):
    consumer.handle(line)                       # must never raise

# Derive the expected counts from the manifest — never hardcode them. An
# earlier revision of this file asserted 15/6/14 against a 21-entry corpus;
# line 22 landed and the numbers were left behind, so the snippet told a
# correct consumer it was broken by one alert. Nothing else here is a number.
accept = [e for e in manifest if e["disposition"].startswith("accept")]
assert consumer.accepted_count == len(accept)
assert consumer.dropped_count == len(manifest) - len(accept)
assert consumer.stored_count == len(accept) - sum(
    1 for e in accept if e["disposition"] == "accept-idempotent")  # redeliveries
assert "&lt;script&gt;" in consumer.rendered_html  # §7.9 — escaped, not stripped
```

Two rules for the replay itself:

1. **Feed it in order and in one pass.** Lines 2 and 3 are deliberately
   out of event-time order; a consumer that sorts by arrival shows them
   inverted (§7.1).
2. **Never let a line abort the run.** Line 10 is truncated JSON. If your
   replay stops there, so would your consumer group in production (§7.10).

## Regenerating

Don't hand-edit the NDJSON — line numbers are the manifest's only key. Add
cases by extending the generator and regenerating both files together.
