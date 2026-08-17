# Proxy log format inventory (prep)

Code-side readiness for multi-vendor proxy exports **without** waiting on
corporate IT. When IT confirms a live export, wiring is: drop sample →
`./replay_sample.sh` → pin `--format` in the connector unit.

Full field-map matrix + residual IT questions:
[`docs/proxy-format-matrix.md`](../../docs/proxy-format-matrix.md).

PR CI matrix (Squid + ≥3 enterprise formats every PR; how to add a vendor):
[`docs/proxy-ci-matrix.md`](../../docs/proxy-ci-matrix.md) +
[`fixture-matrix.json`](./fixture-matrix.json).

## Supported parsers (`proxy_ingest.py` `PARSERS`)

| Format key       | Sniffed by `--format auto` | Input shape | Status |
|------------------|----------------------------|-------------|--------|
| `squid_native`   | yes                        | Squid access.log whitespace fields | **Proven** (original sample + e2e) |
| `jsonl`          | yes (`{…}` lines)          | One JSON object/line; host-bearing field required | **Proven**; enterprise field aliases |
| `zscaler_nss`    | yes (JSON with NSS keys)   | Zscaler Nanolog Streaming Service JSON lines | **Ready** (synthetic sample) |
| `paloalto_csv`   | yes (CSV slash-date rows)  | Palo Alto URL-filter/traffic CSV subset | **Ready** (synthetic sample) |
| `bluecoat_main`  | yes (calendar date + spaces) | Blue Coat / Symantec ProxySG bcreportermain_v1 subset | **Ready** (synthetic sample) |
| `umbrella_csv`   | yes (Umbrella proxy CSV)   | Cisco Umbrella proxy CSV subset | **Ready** (synthetic sample) |
| `auto`           | n/a (meta)                 | Per-line sniff → one of the above | Default for IT replay |

## Enterprise vendor matrix

| Vendor / export | Typical shape | Ready? | How to ingest | Identity presence | Notes |
|-----------------|---------------|--------|---------------|-------------------|-------|
| **Squid** access.log | whitespace native | **Yes** | `--format squid_native` or `auto` | **rfc931** | `samples/squid_access.sample.log` |
| **Zscaler NSS** JSON | JSONL (`url`/`urlhost`/`cip`/`login`/…) | **Yes** | `--format zscaler_nss` or `auto` | **user** (`login`) | `samples/zscaler_nss.sample.jsonl` |
| **Zscaler NSS** CSV | CSV (similar columns) | Partial | Convert to JSONL or map columns | varies | Prefer NSS JSON |
| **Palo Alto** URL / traffic | CSV / syslog CSV | **Yes** (subset) | `--format paloalto_csv` or `auto` | **user** (`srcuser`) | `samples/paloalto_url.sample.csv` — full LEHF may need remap |
| **Blue Coat / Symantec** ProxySG | bcreportermain_v1 | **Yes** (subset) | `--format bluecoat_main` or `auto` | **user** (`cs-username`) | `samples/bluecoat_main.sample.log` |
| **Cisco Umbrella** proxy | CSV | **Yes** (subset) | `--format umbrella_csv` or `auto` | **user** (`Identities`) | `samples/umbrella_proxy.sample.csv` |
| **Cisco Umbrella** DNS-only | CSV (Domain column) | Partial | Map Domain→host via jsonl or widen CSV | **user** if present | Prefer proxy export for HTTP status |
| **Cloudflare Gateway** | JSONL HTTP logs | **Yes** (via jsonl) | `--format jsonl` or `auto` | varies | `host`/`url` + `ClientIP`→`client_ip` |
| **Generic JSONL** identity-bearing | JSONL + login/UPN/nested `identity` | **Yes** | `--format jsonl` or `auto` | **user** | `samples/identity_jsonl.sample.jsonl` |
| **DNS query logs** | vendor-specific | Partial | Convert → `jsonl` `{host,src_ip,ts}` | often **absent** | Query name as host |
| **Firewall URL logs** | vendor-specific | Partial | Convert → `jsonl` or fit `paloalto_csv` | varies | Prefer jsonl |

## Samples on disk

```
collectors/proxy/samples/
  squid_access.sample.log         # Squid native — identity: rfc931
  zscaler_nss.sample.jsonl        # Zscaler NSS JSON — identity: user (login)
  paloalto_url.sample.csv         # Palo Alto URL CSV — identity: user (srcuser)
  bluecoat_main.sample.log        # Blue Coat main — identity: user (cs-username)
  umbrella_proxy.sample.csv       # Cisco Umbrella proxy — identity: user (Identities)
  identity_jsonl.sample.jsonl     # Identity-bearing JSONL — identity: user
```

All samples use RFC1918 clients and synthetic corporate identities. **No real
customer data.**

## Operator: validate an IT sample in one command

```bash
cd collectors/proxy
./replay_sample.sh /path/to/it-export.log          # auto-sniff
./replay_sample.sh /path/to/it-export.log zscaler_nss
./replay_sample.sh /path/to/it-export.log paloalto_csv
./replay_sample.sh /path/to/it-export.log bluecoat_main
./replay_sample.sh /path/to/it-export.log umbrella_csv
```

Exit 0 ⇒ at least one schema-valid `event.v1` AI hit was produced.
Exit non-zero ⇒ zero AI events or schema validation failure — fix format /
detection DB, re-run. Pin the working `--format` on the production connector
once IT confirms the live export.

Batch-check every shipped sample:

```bash
cd collectors/proxy
for f in samples/*; do
  case "$f" in *.md) continue ;; esac
  echo "== $f =="
  ./replay_sample.sh "$f" || exit 1
done
```

CI equivalent (fails the PR job on parse/map regressions):

```bash
python3 scripts/check_proxy_fixture_matrix.py --check
python3 scripts/check_proxy_fixture_matrix.py --self-test
```
