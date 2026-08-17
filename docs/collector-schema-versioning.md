# Collector schema versioning & silent event loss

## Why this exists

A monitoring product that drops events without paging anyone is worse than one
that fails loudly. Collectors already keep a local **rejection ledger**
(`events_rejected`, `batches_fully_rejected`, `last_rejection_at`) and ship it
on every heartbeat as `last_counters`. Until the platform **stored**
those counters and then never surfaced them — so client-side loss was invisible
next to the server-side `rejected_events` DLQ.

## Root cause of the pilot 141,495 drop (device `c771f26f`, host `Hawik`)

| Signal | Value |
| --- | --- |
| `events_rejected` | 141,495 |
| `batches_fully_rejected` | 753 |
| `events_spooled` | 0 |
| `last_rejection_at` | 2026-07-29T11:32:59Z |
| Server `rejected_events` rows (sample) | `unsupported schema_version: 1`; schema mismatch (`unexpected property 'actor'`, missing `host_ref`/`source`/`match_flags`) |

**What happened.** A collector build still emitting **schema v1** (and at least
one experimental shape carrying `actor`) kept POSTing batches to ingest. Ingest
rejected them (fail-closed schema validation). The collector counted the loss
locally, drained the spool (`events_spooled=0`), and kept heartbeating green.
Server DLQ only retained a handful of sample rows (not 141k), so the platform
looked healthy while **5× more events were discarded client-side than were
ever stored**.

The drop storm stopped when the collector stopped sending bad batches (~30h
diagnosis). Lifetime counters remain on the device row so the
incident is still visible as historical loss.

## Contract: what an out-of-date collector must do

1. **Ingest stays fail-closed** on schema validation. Unsupported
   `schema_version` or unknown required fields → batch rejected. Do not silently
   coerce unknown shapes into "best effort" events.
2. **Collector must not treat a rejected batch as success.** Rejection ledger
   increments (`events_rejected`, and `batches_fully_rejected` when the whole
   batch is refused). Spool entries for fully-rejected batches are dropped so
   the spool does not grow forever — but the **count** is retained and reported
   on heartbeat.
3. **Heartbeat is the platform's loss signal.** `last_counters` is authoritative
   for client-side loss. Operators read it via `/api/fleet` projected fields
   (`events_rejected`, `batches_fully_rejected`, `drop_active`) and the
   `collector_drops` system-status tile.
4. **Upgrade path.** Collectors must ship with a schema version the current
   ingest accepts. When ingest raises the minimum version, old collectors will
   start rejecting every batch — that is intentional. The drop tile + fleet
   column page within one heartbeat interval (`COLLECTOR_DROP_RECENT_SEC`,
   default 900s) so the upgrade failure is loud.
5. **Do not re-label historical loss as healthy.** Lifetime counters stay on the
   device until the collector process resets its ledger. Active alerting uses
   `last_rejection_at` recency so a fixed host does not page forever.

## Platform surfaces

| Surface | Behaviour |
| --- | --- |
| `GET /api/fleet` | Projects drop fields per device; `dropping` rollup count for `drop_active` devices. Never returns raw `last_counters` or `device_token_hash`. |
| `GET /api/system/status` tile `collector_drops` | `broken` if any device is actively dropping; `degraded` if lifetime counters exist but none are recent; `ok` otherwise. |
| System-status alerter | When `SYSTEM_STATUS_ALERTS=1` + `ALERT_BUS_URL`, breach tiles (including `collector_drops`) XADD onto the security alert bus. |
| Fleet UI | "Dropping" card + per-device ingest-health column. |

## Reproduce (dev)

```bash
# Point a schema-v1 (or deliberately invalid) batch at ingest with a valid device token.
# Expect: 4xx/partial rejection from ingest, collector ledger increments, next
# heartbeat carries events_rejected > 0 and last_rejection_at ≈ now.
# Within COLLECTOR_DROP_RECENT_SEC:
#   curl -H "Cookie: …" $API/api/fleet | jq '.dropping, .devices[]|select(.drop_active)'
#   curl -H "Cookie: …" $API/api/system/status | jq '.tiles[]|select(.id=="collector_drops")'
```

## Related

- rejection ledger on collectors
- enrollment + fleet coverage
- system status tiles + alert bus publisher
- `docs/identity-mapping-design.md` — attribution is independent of drop health
