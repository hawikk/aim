# OS egress collector

On-device capture surface for **non-IDE AI SaaS usage** (ChatGPT web, Claude.ai
web, and other catalogue domains). Decision record:
`../../docs/aim-321-capture-surface-decision.md`. Consent/notice bar (must be
acked before capture): `../../docs/privacy/aim-321-os-egress-consent-notice.md`.

## What it does

1. Reads structured **DNS / flow / SNI metadata** records (JSONL) — destination
   hostname only; never URL paths, query strings, or bodies.
2. Matches hostnames against the AI domain catalogue
   (`../proxy/endpoints.json`, optionally merged with a shadow-AI catalogue
   JSON). Catalogue growth expands coverage
   **without a code change**.
3. Emits canonical v1.9+ `ai-usage-event` records with `source: "os_egress"`.
4. **Refuses to capture** until the notice acknowledgment gate is satisfied
   (privacy bar).

## Quick start

```bash
# notice ack required (or set AIM_OS_EGRESS_NOTICE_ACK=1 for tests)
export AIM_OS_EGRESS_NOTICE_ACK=1
export AIM_HASH_SALT=dev-salt-not-for-production

python3 -m os_egress \
  --input samples/chatgpt-claude.jsonl \
  --endpoints ../proxy/endpoints.json \
  --sink stdout
```

Tests:

```bash
python3 -m pytest collectors/os-egress/tests -q
```

## Input record shape (JSONL)

```json
{"ts": "2026-07-29T12:00:00Z", "host": "chatgpt.com", "process_class": "browser"}
```

| Field | Required | Notes |
|---|---|---|
| `host` or `dest_host` | yes | Destination hostname (no path/query) |
| `ts` | no | RFC 3339; default now UTC second |
| `process_class` | no | `browser` \| `desktop_app` \| `unknown` — optional, off by default on wire |
| `device_id` | no | Stable device id for host_ref; else hostname / env |

Platform agents (Windows ETW DNS, macOS NE, Linux eBPF/resolved) should
normalize into this shape. The collector core is deliberately adapter-thin so
style surface plugins can feed it later.

## Privacy

- Metadata only.
- Allowlist match only — non-catalogue destinations produce **zero** events.
- Notice gate: see consent doc §5.
- Process **command lines** and full URLs are stripped if a buggy adapter
  includes them.
