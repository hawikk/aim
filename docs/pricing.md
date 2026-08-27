# Pricing

Public tariff for AIM. These are the only numbers; do not invent others.
Copy only — there is no Cloud checkout or metering in this tree.

| Tier | Price | Humans | Agents | Start |
|---|---|---|---|---|
| **Community** | Free | Uncapped | Uncapped | [GitHub](https://github.com/hawikk/aim) / `pipx` |
| **Cloud** | 3 agents free, then **$2 / agent / month** (USD) | Uncapped | Metered on Cloud | [Request Cloud access](mailto:sales@getaimonitoring.com?subject=AIM%20Cloud) |
| **Enterprise** | Contact sales | Uncapped | Custom | [Contact sales](mailto:sales@getaimonitoring.com) |

Tax exclusive. No public annual SKU.

## Community — free, uncapped

Community is free. Self-host it or run `aim personal`. Uncapped seats,
uncapped agents, Apache-2.0, no DRM, no phone-home. Personal mode makes
zero outbound calls.

A 700-person fleet running Community is a distribution win, not a license
violation. There is no 3-seat cap, no 5-seat cap, and no seat file.

```bash
pipx install aimonitoring-security && aim personal
```

Self-host the dashboard: [self-host](self-host.html) (HTML) /
[compose quickstart](deployment/self-host-quickstart.md).

## Cloud — hosted, copy only

Cloud: 3 agents free, then $2 per monitored agent / month. We host the
dashboard. 30-day retention. Request access.

A **monitored agent** on Cloud is one inventory object AIM is watching:

1. A coding-agent install (one product on one host/user). Two products on
   one laptop = two agents.
2. An MCP server instance (one configured server `name` at user or project
   scope on one host).

Humans, events, tokens, findings, and anything that exists only in
`aim personal` or Community self-host are never the SKU.

Until billing ships, fulfillment is still a human. The list price is
published so you do not have to negotiate $2. This is **not**
"contact sales for a quote."

[Request Cloud access](mailto:sales@getaimonitoring.com?subject=AIM%20Cloud)

Volume (about 250 Cloud agents) or any SSO / enforcement / evidence / DPA
/ SLA / air-gap need → Enterprise.

## Enterprise — contact sales

Enterprise: SSO, enforcement packs, evidence, custom retention, DPA, SLA,
air-gap. Contact sales.

No public dollar number. Self-hosted **paid** (you run it; we license
packs and support) is also Enterprise.

[Contact sales](mailto:sales@getaimonitoring.com)

## What this page does not do

- No Stripe, quota service, license key, or usage meter in this repo
- No DRM on the Apache-2.0 tree
- No path that sends prompt text or tool arguments off the box
