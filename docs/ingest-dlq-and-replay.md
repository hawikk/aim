# Ingest pipeline: DLQ, replay, and backpressure

Operational runbook for `services/ingest`. Audience: on-call engineer / security ops.

## TL;DR

- Accepted events are stored in `events`, **idempotent on `event_id`** — replays are always safe.
- Rejected (schema-invalid) events go to the **DLQ table `rejected_events`** — error text, SHA-256 payload hash, top-level key names only. **The rejected payload is never persisted** (an invalid event may contain arbitrary content; storing it would break the metadata-only privacy contract).
- Replay = re-POST the same batch. Duplicates are counted, not double-stored.

## Dead-letter handling

Every event that fails edge validation (`src/schema.ts`, contract) is recorded:

```sql
SELECT received_at, batch_index, error, payload_hash, payload_keys
FROM rejected_events
ORDER BY id DESC LIMIT 20;
```

- `error` — validation message paths only; never payload values (`formatError` strips ajv params).
- `payload_hash` — SHA-256 of the serialized payload. Correlate with the sending collector: ask the endpoint to hash its local copy and compare, without either side transmitting content.
- `payload_keys` — top-level JSON key names, for triage ("which field shape did this collector emit?").

Unsupported `schema_version` majors are rejected loudly with the version named in the error, so a misconfigured collector fleet is visible in one query:

```sql
SELECT error, count(*) FROM rejected_events GROUP BY error ORDER BY count DESC;
```

## Replay procedure

1. **Collector-side retry** (normal case): collectors retry failed batches with backoff. Because inserts are `ON CONFLICT (event_id) DO NOTHING`, any retry window is safe — no dedupe state to manage.
2. **Full replay after outage**: re-send the stored batches from the collector's local spool to `POST /v1/events`. The response reports `accepted` (newly stored) and `duplicates` (already stored) so progress is observable.
3. **Verify zero loss** after replay:

   ```sql
   SELECT count(*) AS stored, count(DISTINCT event_id) AS distinct_ids FROM events;
   ```

   `stored = distinct_ids` and the count matches the spooled total. The acceptance suite (`scripts/ingest-acceptance.mjs`) automates this check, including a replay-fallback path when the DB is not directly reachable.
4. **DLQ reprocessing**: after fixing a collector that emitted invalid events, re-send the corrected events with their **original `event_id`s**. Events that were never inserted land exactly once; no manual DLQ draining is needed. `rejected_events` rows are an audit trail, not a queue — they are not deleted on successful reprocessing.

## Backpressure and rate limiting (v0)

- **Batch cap**: max 500 events per request (`MAX_BATCH_SIZE`), larger batches get `413` and can be split client-side.
- **Body cap**: 5 MiB per request (Fastify `bodyLimit`).
- **Sink backpressure**: inserts flow through the `pg` pool; when Postgres saturates, request latency rises and Fastify's connection backlog absorbs bursts. Collectors must treat `5xx` as retryable with exponential backoff.
- **Auth**: bearer tokens (constant-time compare); per-endpoint identity is the collector token + attested host/user refs. mTLS at the platform ingress is the production hardening path (see `docs/architecture.md`).

## Retention

Retention TTLs are defined by the privacy pack. Enforcement is a scheduled `DELETE ... WHERE received_at < now() - interval '<TTL>'` job against `events` and `rejected_events`; the job ships with the pilot deployment tooling. The schema is metadata-only by contract, so retention applies to pseudonymized metadata only — no content stores exist to purge.

## Verification

- Unit/integration: `pnpm --filter @aimon/ingest test` (31 tests: auth, schema validation, mixed batches, idempotent replay, DLQ privacy, identity enrichment, observability).
- End-to-end acceptance incl. 5k events/min load test and zero-loss check: `INGEST_TOKEN=... node scripts/ingest-acceptance.mjs` (requires the local `aim-local` compose stack).
