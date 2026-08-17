# Proxy/network log ingestion

Day-1 breadth: detect AI coding tool usage across the fleet using network
telemetry that already exists — no endpoint agent required. This is the
breadth half of the hybrid collection strategy locked; endpoint
collectors add depth.

## What it does

1. Reads proxy/network logs (`squid_native`; `jsonl` / `zscaler_nss` for
   JSON-line exports with enterprise field aliases; `paloalto_csv` for
   Palo Alto URL-filter CSV; `bluecoat_main` for Blue Coat / Symantec
   ProxySG; `umbrella_csv` for Cisco Umbrella proxy CSV; `auto` — the
   default — sniffs each line, which is how we replay unknown samples
   from IT). Pin an explicit format in production once IT confirms the
   export shape. Vendor readiness: [`FORMATS.md`](./FORMATS.md).
   Field maps + residual IT questions:
   `../../docs/proxy-format-matrix.md`.
2. Matches destination hostnames against the AI endpoint detection
   database (`endpoints.json` — coding-AI SaaS catalogue, suffix-matched, with
   sanctioned/unapproved flagging per policy; refreshed).
3. Emits normalized canonical v1 events
   (`../../packages/schema/schema/v1/ai-usage-event.schema.json`),
   metadata only: hostnames, never URL paths or query strings.
4. Forwards to a sink: stdout, file, or the ingestion API
   (batched HTTP POST, bearer auth, retry with backoff).
5. Produces a fleet coverage report (distinct sources seen vs expected
   fleet size) with `--coverage --expected-fleet 700`.

## Quick start

```bash
cd collectors/proxy
python3 proxy_ingest.py --collector proxy-squid-dc1 --format squid_native \
    --input samples/squid_access.sample.log --coverage --expected-fleet 700

# Multi-vendor synthetic corpus — same pipeline, auto-sniff:
./replay_sample.sh samples/zscaler_nss.sample.jsonl
./replay_sample.sh samples/paloalto_url.sample.csv
./replay_sample.sh samples/bluecoat_main.sample.log
./replay_sample.sh samples/umbrella_proxy.sample.csv
./replay_sample.sh samples/identity_jsonl.sample.jsonl
```

Run tests:

```bash
python3 -m unittest discover -s collectors/proxy/tests
```

## Blocklist export + would-block reporting (phase 2b)

The same `endpoints.json` intelligence feeds enforcement IT already owns:
`export_blocklist.py` exports unapproved domains as a corporate-proxy
blocklist (Zscaler custom URL category / Squid `dstdomain` / review CSV /
JSON manifest), and `would_block_report.py` reports what stored events
*would* have been blocked had the list been enforced.

```bash
# enforce tier (default): unsanctioned employee-tool domains only.
# provider-api rules (OpenAI direct, OpenRouter) are review-tier (
# shared with company-built apps) and need IT/Security sign-off first.
python3 export_blocklist.py --format domains [--tier enforce|review|all]
python3 export_blocklist.py --format squid --output squid-dstdomain.conf

# would-block report from an events export (JSONL):
psql "$DATABASE_URL" -At -c "select payload from events;" > events.jsonl
python3 would_block_report.py --input events.jsonl [--since 2026-07-08T00:00:00Z]
```

Safety invariant: the exporter refuses to run if any blocklist domain would
also match a sanctioned-tool domain.

### Validate an IT sample in one command

`replay_sample.sh` is the acceptance check — exits non-zero if the sample
yields zero AI events or any event fails schema validation:

```bash
./replay_sample.sh /path/to/it-sample.log              # auto-sniffs format
./replay_sample.sh /path/to/it-sample.log zscaler_nss  # pin when known
./replay_sample.sh /path/to/it-sample.log paloalto_csv
./replay_sample.sh /path/to/it-sample.log bluecoat_main
./replay_sample.sh /path/to/it-sample.log umbrella_csv
./replay_sample.sh /path/to/it-sample.log squid_native
```

Formats ready for drop-in replay today (synthetic samples under `samples/`):
Squid native, Zscaler NSS JSON, Palo Alto URL CSV subset, Blue Coat main,
Cisco Umbrella proxy CSV, identity-bearing JSONL. See [`FORMATS.md`](./FORMATS.md)
and `../../docs/proxy-format-matrix.md`.

## Production deployment shape

- One connector instance per log source, run as a cron/systemd timer or a
  tail-follow daemon. `--collector` identifies the instance
  (e.g. `proxy-squid-dc1`) and is stamped on every event.
- Ship logs off-box via existing infra (rsyslog forward to the connector
  host, or cloud proxy API export → `jsonl` adapter).
- `--sink http --ingest-url https://ingest.aim.internal/v1/events
  --ingest-token $AIM_INGEST_TOKEN` posts batches to the ingestion
  API (`services/ingest`). Verified end-to-end against the local compose
  stack (sample squid log → API → Postgres, idempotent on replay).
  `--sink file` + any log shipper also works.
- Detection DB updates are PR-reviewed; cadence weekly during pilot.

## Event contract

See `../../packages/schema/schema/v1/ai-usage-event.schema.json` (canonical
schema; the collector self-checks every event against its hard
constraints before emitting). Key properties:

- `event_id` is a deterministic UUID derived from ts+src+host+action, so
  re-ingestion is idempotent (ingest dedupes on `event_id`).
- `ts` is RFC 3339 UTC at second precision (the schema pattern forbids
  fractional seconds).
- `host_ref` is HMAC-SHA256 of `src_ip` (the most stable host identifier a
  proxy sees); `user_ref` stays null until identity mapping.
  Salt from `AIM_HASH_SALT` (KMS-distributed in production) or a local
  0600 salt file in dev/pilot.
- Sanctioned tools (Claude Code, Cursor, Kilo Code) emit their normalized
  `tool` id; everything else emits `tool: "other"` with `tool_raw` naming
  the detected tool and a `policy:unapproved-tool` match flag
  (observe-only — detection and alerting, no blocking).
- `model`, token counts, and cost are null — not observable at the
  network level. `session_id` is a synthetic per-source/per-day
  correlation id, not a tool session.

## Identity attribution

The proxy collector does **not** emit the `collector: {device_id, os_user}`
batch-envelope block that endpoint collectors use: it runs off-box and the
log formats it consumes carry no OS identity, so there is nothing to attest.
Proxy-sourced events are therefore stored **unattributed**
(`user_pseudonym` NULL, counted in `ingest_events_unresolved_total`) — this
is expected, not a gap in the endpoint rollout.

Attribution of proxy events is only possible if proxy-authenticated identity
(e.g. Zscaler/Bluecoat user fields) is mapped to the directory later; that
is a separate, unscheduled piece of work and would arrive as a new adapter
field rather than envelope attestation. Until then, endpoint collectors are
the depth/attribution source and proxy events remain the breadth source.

## Source-class attribution

Each event's `src_ip` is classified **before pseudonymization** against the
subnet inventory (`subnets.json`, `--subnets` to override) into
`traffic_class`: `application` (server/DC + CI-runner ranges), `employee`
(endpoint ranges), or `unknown` (no match). Only the class label crosses the
wire — never the IP. Fail-safe semantics: `unknown` keeps the existing
verdict behavior, and an equal-specificity overlap resolves to `employee`.

Rules in the `provider-api` category of `endpoints.json` (direct LLM APIs
usable by both employee tools and company-built software — OpenAI,
Anthropic, Azure OpenAI, AWS Bedrock, Google Gemini/Vertex, Mistral,
Cohere, Groq, xAI, OpenRouter) do **not** emit the employee-tool
`policy:unapproved-tool` verdict for `application`-classified traffic.
Employee and unknown sources are unchanged, and unsanctioned non-provider
rules (e.g. DeepSeek, Amazon Q) stay flagged even from servers — that is the
shadow-AI-in-software signal. The App-LLM dashboard meters only the
`provider-api` provider set; catalogue change log:
`docs/app-llm-provider-catalogue.md`.

Until the network team delivers the real server/CI/endpoint ranges, the
shipped `subnets.json` is empty: every source classifies `unknown` and
behavior is byte-identical to the baseline (a startup note on stderr
says so). Events also carry `bytes_up/down`, `http_status`, and
`duration_ms` (schema v1.4) when the log source reports them — volume and
status metering for the App-LLM view.
