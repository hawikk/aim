# API read-path pagination (`/api/users`, `/api/fleet`)

(gap)
**Owner:** engineering (API) · Frontend consumes in a follow-up
**Status:** Implemented — offset pagination with `total`

---

## 1. Why

At 5k seats, full-list JSON for Users and Fleet exceeds transfer budgets from
`docs/frontend-performance-budget.md` §4.1:

| Endpoint | 5k synthetic size | Payload budget |
|---|---|---|
| `GET /api/users` (full list) | ~1.0 MB | ≤ 350 KB |
| `GET /api/fleet` (full list) | ~2.2 MB | ≤ 500 KB |

`/api/users` previously used a silent `LIMIT 500` with no `total`, so a 700-seat
active population could hide ~200 users. `/api/fleet` returned every enrolled
device unbounded.

---

## 2. Contract

Both endpoints keep their existing privacy gates (analyst+). Pagination does
**not** weaken authz or reveal additional identity fields.

### `GET /api/users?days=N[&limit=&offset=&format=csv]`

| Query | Default (JSON) | Max (JSON) | Default/Max (CSV) |
|---|---|---|---|
| `limit` | 100 | 100 | 10_000 |
| `offset` | 0 | — | 0 |

JSON response fields (additions):

```json
{
  "rangeDays": 30,
  "total": 712,
  "limit": 100,
  "offset": 0,
  "note": "…",
  "users": [ /* at most `limit` rows, ordered by tokens DESC */ ]
}
```

- `total` is the full distinct-pseudonym count in range (not the page length).
- CSV export remains analyst+-gated; only CSV may use `limit` > 100.
- Ordering unchanged: highest token volume first.

### `GET /api/fleet[?limit=&offset=]`

| Query | Default | Max |
|---|---|---|
| `limit` | 100 | 100 |
| `offset` | 0 | — |

JSON response fields (additions):

```json
{
  "deployed": 5120,
  "total": 5120,
  "limit": 100,
  "offset": 0,
  "healthy": 4800,
  "stale": 200,
  "dead": 80,
  "never_seen": 40,
  "silent": 280,
  "coverageGaps": 320,
  "dropping": 12,
  "lastVerifiedAt": "…",
  "devices": [ /* at most `limit` rows, enrolled_at ASC */ ]
}
```

- Rollup counters (`deployed`, `healthy`, …) are **fleet-wide**, not page-local.
- `total` equals `deployed` (non-revoked enrolled devices).
- `device_token_hash` and raw `last_counters` remain withheld.

---

## 3. p95 latency budgets

Warm Postgres, 700-seat synthetic or pilot volume. Implementing pagination
keeps these achievable at 5k when clients request ≤ 100 rows:

| Endpoint | p95 budget | Payload budget (uncompressed JSON) |
|---|---|---|
| `GET /api/me` | ≤ 50 ms | ≤ 2 KB |
| `GET /api/overview?days=30` | ≤ 300 ms | ≤ 100 KB |
| `GET /api/findings?limit=200` | ≤ 250 ms | ≤ 250 KB |
| `GET /api/users?days=30` (paginated) | ≤ 400 ms | ≤ 350 KB at 700 rows; page ≤ 100 for 5k |
| `GET /api/fleet` (paginated) | ≤ 400 ms | ≤ 500 KB at 700 devices; page ≤ 100 for 5k |
| `GET /api/flags?days=30` | ≤ 300 ms | ≤ 150 KB |
| `GET /api/unapproved?days=30` | ≤ 250 ms | ≤ 50 KB |

Honesty rule (unchanged): never imply full coverage from a
truncated page — UI must surface `total` ("showing N of M").

---

## 4. Client follow-up

Frontend should:

1. Request `limit≤100` on Users/Fleet tables.
2. Show "showing `users.length` of `total`" (or fleet equivalent).
3. Page via `offset` (or stop and export CSV for full dump).

Server work for item 8 of the path-to-5k list (p95 load test at 5k synthetic
rows) is separate from this shape change.
