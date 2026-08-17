# Auditor privacy overview — metadata-only AI monitoring

**Audience:** Internal / external auditors, works-council reviewers, Legal  
**Length:** two pages
**Status:** shipping posture (policy) · **Date:** 2026-08-01
**Policy owner:** Security

This is the auditor-facing privacy one-pager. It states what the platform
collects, what it never collects, and **how to verify those claims offline**
without trusting a live dashboard.

---

## Page 1 — What we claim

### Purpose of the product

AI Monitoring gives a 700+ person company visibility into which AI coding tools
(Claude Code, Cursor, Kilo Code, and others) engineers use, and surfaces
security findings — **without reading prompts or code**.

Security is the primary purpose. Employee content is not.

### Hard privacy lines (non-negotiable)

| We collect | We never collect |
|---|---|
| Tool / model / provider identity | Prompt text or response text |
| Pseudonymous user / host / repo refs | Emails, names, raw hostnames, IPs |
| Token counts, cost estimates, timestamps | File contents, diffs, snippets |
| Boolean detection flags + detector name | Matched secret / PII **content** |
| Enforcement decision metadata | Command lines, tool arguments, paths |
| Aggregate compliance posture | Screen content, keystrokes, idle time |

**Metadata-only is the default and only path.** There is no “reveal prompt”
mode, no content export, and no client-side workaround that reintroduces
bodies. Invalid events are stored as hash + key names only — never the raw
payload (an invalid payload could contain anything).

### Pseudonymization at the edge

`user_ref`, `host_id`, `team_ref`, and `repo_ref` are salted HMACs produced on
the endpoint. The salt lives outside this platform. Stored telemetry cannot be
reversed by the platform alone. Role-gated identity reveal (when authorized)
is audited; it is not available in auditor offline packs.

### Retention (enforced in code)

| Data class | Default retention |
|---|---|
| Usage events | 90 days |
| Findings | 365 days |
| Audit trail | 730 days |

Ordering `audit ≥ findings ≥ events` is enforced. Purges leave metadata-only
audit records. Knobs and rationale:
[`data-minimization-and-pseudonymization.md`](./data-minimization-and-pseudonymization.md).

### Honest residual risk

Metadata-only does **not** mean “nothing personal can be inferred.” Flags,
tool names, and small-team patterns can still describe employee activity.
See the reconstruction risk report
.
That report **does not** recommend prompt capture as a mitigation.

---

## Page 2 — How to verify offline (no-content + evidence)

Auditors should not need a live session or an engineer to re-prove the two
claims that matter: **(1) the wire cannot carry content fields**, and
**(2) a compliance evidence pack is intact.**

### A. No-content claim (schema + emit)

**Continuous CI gate** (same command auditors can run from a clean checkout):

```bash
# Same gate CI runs on every PR that touches collectors / schema / ingest
python3 scripts/no_content_egress.py --check

# Prove the rules are alive (mutates a temp tree; expects each rule to fire)
python3 scripts/no_content_egress.py --self-test

# Machine-readable report for evidence binders
python3 scripts/no_content_egress.py --check --json-report nce-report.json
```

| Layer | What a pass means |
|---|---|
| **Schema** | Objects stay closed (`additionalProperties: false`); forbidden content property names are not declared |
| **Samples** | Valid fixtures have no content keys; injecting ~40 banned keys is rejected; required invalid fixtures still fail |
| **Emit** | Adapter `strip_forbidden` drops content keys before the event hits the wire |

**Source of truth:** [`scripts/no_content_egress.py`](../../scripts/no_content_egress.py)  
**Operator guide:** `docs/security/no-content-egress.md`  
**Field-level DPIA feed:** [`packages/schema/FIELDS.md`](../../packages/schema/FIELDS.md) · schema package README

Pin fixtures under `packages/schema/examples/` (e.g.
`invalid-contains-prompt-text.json`, `invalid-response-body.json`,
`invalid-message-content.json`, `invalid-tool-call-arguments.json`).

### B. Compliance evidence pack (auditor self-serve)

From the product **Compliance** tab → **Download offline pack (.zip)**:

| File | Verifies |
|---|---|
| `README.txt` | How to check integrity with stock tools |
| `SUMMARY.txt` | One-page executive posture |
| `report.json` / `report.csv` | Same numbers as the live report |
| `evidence-bundle.json` | Signed bundle (hash-linked to the audit chain) |
| `SHA256SUMS` | GNU `sha256sum -c` inventory |
| `MANIFEST.json` | Machine inventory + pack hash + verify hooks |

**Integrity (no Node, no secrets):**

```bash
unzip aim-compliance-offline-pack_*.zip && cd <extracted>
sha256sum -c SHA256SUMS   # every line must be OK
```

**Optional cryptographic chain verification (ops-held key):**

```bash
AUDIT_LOG_PATH=/var/lib/aim/audit.jsonl AUDIT_HMAC_KEY=... \
  node scripts/verify-compliance-bundle.mjs evidence-bundle.json
```

Exit 0 = structure, content hash, HMAC signature, full audit-chain walk, and a
`compliance.export` record sealing **this** bundle hash all pass.

**Implementation hooks (code):**

| Hook | Path |
|---|---|
| Offline pack builder (ZIP, checksums, README) | `apps/web/public/lib/offline-pack.js` |
| Compliance UI download | `apps/web/public/compliance.js` → “Download offline pack” |
| Bundle crypto verifier | `scripts/verify-compliance-bundle.mjs` → `apps/api/src/compliance-bundle.js` |
| No-content CI harness | `scripts/no_content_egress.py` |
| Framework mapping + retention | `docs/compliance-evidence.md`, `policies/compliance/framework-map.yaml` |

### C. What this one-pager does **not** prove

- That every endpoint in the fleet is enrolled (see Coverage / Fleet views).
- That a customer’s works-council filing is complete (use the DPIA pack + Legal).
- That residual inference risk is zero.

### Related deeper docs

| Doc | When to open it |
|---|---|
| [`data-minimization-and-pseudonymization.md`](./data-minimization-and-pseudonymization.md) | Field-by-field necessity + retention knobs |

---

*End of auditor privacy overview (2 pages). For product questions, route through
Security; for policy reversals (e.g. content capture), escalate to the policy owner
engineering will not route around these lines.*
