# sentinel — the triage agent

Reads the unified alert bus, decides what a human needs to know, and says it
once, with a fix attached.

```
   pillars ──XADD──▶ redis stream ──XRANGE──▶ sentinel ──▶ Slack / webhook / email
  (cnapp, aim,        secstack:alerts:v1        │
   gatehouse)                                   ├─▶ incidents + decision log (SQLite)
                                                └─▶ LLM endpoint (metadata only)
```

## What it does, in the order it does it

1. **Reads** the bus by cursor (no consumer groups, no XACK, no writes at all).
   Every entry is validated against the *consumer profile* of the alert
   contract and projected onto known fields before anything touches it.
2. **Correlates.** Same `dedupe_key` → a restatement. Same root cause
   (`pillar` + `finding_type` + account, configurable) inside a 15-minute
   window → one incident, however many resources it touches. Outside the
   window → a recurrence, which is news.
3. **Triages** with a configurable LLM: what happened in plain English, blast
   radius, and whether it looks real. Metadata only crosses that hop.
4. **Proposes a fix** from a reviewed catalogue — Terraform, CLI or console
   steps, copy-paste ready. The LLM writes prose; it never writes commands.
5. **Notifies** every enabled channel, records each attempt, and retries what
   failed.
6. **Logs the decision** — including the decisions to stay quiet.

Medium and low findings never page; they roll into a daily digest.

## The rule this service is built around

> A finding that disappears without an error is worse than a false positive.

So: an LLM outage still pings (labelled as un-triaged). A delivery failure is
recorded, retried and counted in `/healthz`. A bus that has been unreadable for
five minutes produces a notification *about the sentinel*, because a stack that
has gone blind must not look like a quiet week. A crash mid-page re-pages on
restart rather than filing the alert as already-seen. Every one of those has a
test in `tests/test_degrade.py`, and they are the tests to run first after a
change.

## Running it

```bash
docker compose up -d sentinel                 # in the stack
docker compose run --rm sentinel-tests        # acceptance suite, real bus

# locally
pip install -e services/sentinel
SENTINEL_CONFIG=deploy/sentinel.yml sentinel serve
sentinel once                                 # drain the backlog and exit
sentinel decisions --limit 10                 # why did it page / not page
sentinel health
```

Configuration: copy `sentinel.example.yml`. Structure goes in the YAML,
credentials go in `.env` as `env:NAME` references — a literal webhook URL in
the YAML is rejected at startup, because it is a bearer credential.

## Demo: the ST8 public-bucket scenario

```bash
# one critical alert
python services/sentinel/demo/seed_st8.py --url redis://localhost:6379/0

# the storm case: 12 buckets from one bad apply → ONE message
python services/sentinel/demo/seed_st8.py --burst 12
```

The seeder is deliberately outside the `sentinel` package: the service is
read-only on the bus, and an `XADD` one import away from the consumer is an
`XADD` someone will eventually call.

## What it cannot do, on purpose

- **No cloud or repo write credentials** (D4). No cloud SDK is installed. Every
  remediation is text a human chooses to run.
- **No draft PRs in v1.** The config key exists and is `false`; setting it to
  `true` makes the service refuse to start with a pointer to the follow-up
  work, rather than quietly continuing to send copy-paste-only proposals while
  an operator believes PRs are being opened.
- **No policy decisions.** `page_from` is the shipped proposal; the threshold
  belongs to Security.

## Data it stores, and for how long

| Table | Why | Retention |
|---|---|---|
| `incidents`, `incident_alerts` | correlate bursts; know what a thread covers | 90 days |
| `decisions` | answer "why did it page / not page" | 90 days |
| `seen` | idempotency across restarts | 90 days |
| `digest_items` | the daily rollup | dropped 7 days after digesting |
| `outbox` | prove a notification was (or was not) delivered | 30 days |

No alert *content* beyond the bus contract's own metadata is stored — the alert
is a pointer to a finding in a pillar, not a copy of it. No prompt text, no
secret values, no plaintext identity: `subject_ref` is an HMAC pseudonym by
contract, and the LLM payload is an allowlist (`triage._prompt_payload`), not a
denylist.
