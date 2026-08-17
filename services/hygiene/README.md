# hygiene — secrets & token hygiene (pillar 4)

Answers three questions about a repository that no other pillar answers:

1. **What credentials are still recoverable from this repo's history?**
2. **What is the working tree committing that it should not be?**
3. **What can the tokens we hold actually do?**

Findings go to a markdown report and onto the cross-pillar alert bus as
`security.alert/v1.1`. A credential verified to still authenticate publishes as
`critical`, which is what sentinel pages on.

## Why this is not "we already run gitleaks"

gatehouse (pillar 3) runs gitleaks over a **pull request's worktree**. It
answers *"does this PR add a secret?"* — and it must, because re-reporting every
historic leak on every PR is how a gate gets ignored.

This pillar runs `gitleaks git` over the **full object graph**, and adds two
checks that are not pattern matching at all.

Measured on the seeded fixture in `src/hygiene/demo/seed_repo.py`, where an AWS
key was committed in 2025 and deleted two commits later:

| | worktree scan (gatehouse) | history scan (hygiene) |
|---|---|---|
| findings | 2 | 4 |
| the deleted AWS key | **missed** | found, at the commit that introduced it |

That key is live until somebody rotates it. The file being gone changes nothing.

## The three checks

### 1. History (`checks/history.py`)

Full-history gitleaks, plus **liveness verification**: for each leaked
credential we call the issuer's own read-only identity endpoint to find out
whether it still works.

Severity is driven entirely by that answer:

| liveness | severity | rationale |
|---|---|---|
| `live` | `critical` | the window is open right now — sentinel pages |
| `unknown` | `high` | could not check; never treated as safe |
| `dead` | `medium` | purge still owed, nobody needs waking |

Only `live` reaches `critical`. An unreachable issuer must never manufacture a
page, and it must never suppress one either.

### 2. Worktree hygiene (`checks/worktree.py`)

Three failures that slip past any pattern scanner:

- **A tracked `.env`.** Every value in it is a credential by convention.
  `DB_PASSWORD=hunter2` matches no rule — it has no entropy and no prefix. The
  file *being tracked* is the finding. `.env.example` is not.
- **Inline credentials in config.** `postgres://user:pw@host` in a
  `database.yml` is a live database password. Verified against gitleaks 8.28:
  it reports nothing for that line. This check keys on *structure* — a userinfo
  field, a `password:` assignment — rather than on entropy.
- **`.gitignore` gaps.** The only preventive finding the pillar produces, and
  the one that stops the *next* leak.

Everything works from `git ls-files`, never a directory walk: a `.env` sitting
in a working directory is normal and flagging it trains people to ignore us.

### 3. Token scope audit (`checks/tokens.py`)

Compares a token's granted scopes against the documented minimum, and
deep-links over-scoped **cloud** principals into Cloud Sentry's CIEM view
rather than rebuilding a policy evaluator here (D2).

> **The trap this check is built around.** Fine-grained PATs, GitHub App
> installation tokens and Actions' `GITHUB_TOKEN` return **no**
> `x-oauth-scopes` header. Parsed naively that becomes an empty scope list,
> which sorts as the *least* privileged token possible — so a fine-grained PAT
> with org-wide admin would audit as cleaner than a read-only classic token.
> An absent header produces its own `unauditable_token` finding. "Could not
> determine" and "determined to be fine" are different answers.

## Handling of secret values

- **Never stored, never displayed, never transmitted anywhere but the issuer.**
- `Finding` has no field a raw secret fits in. Raw values exist only inside the
  scanning functions and are dropped before they return — so "we accidentally
  logged it" is a type error, not an incident.
- Reports and alerts carry a **mask** (issuer prefix + last 4 — enough to pick
  the right key out of a vault, not enough to authenticate) and a **keyed HMAC
  fingerprint**. The key is generated per install, lives `0600` beside the
  state DB, and never leaves the box, so a stolen findings table is not a
  secret-recovery oracle. That matters because a large share of real leaked
  credentials are low-entropy (`admin123`), and a plain SHA-256 of those is
  reversible in seconds.
- gitleaks writes matched secrets to its JSON report in the clear. We write it
  to a `0700` directory **outside** the repo and unlink it in a `finally`.
- Findings state is retained **30 days** and purged at the start of every run.

The one deliberate exception: liveness verification sends the credential to the
party that issued it. That is unavoidable — only the issuer can say whether a
key is live — and it is bounded by a hardcoded host allowlist, one attempt, no
retries. Turn it off with `liveness.enabled: false` or `HYGIENE_LIVENESS=off`.

## Running it

```bash
# on demand, against any checkout
hygiene scan /repos/ai-monitoring

# without sending any credential anywhere
hygiene scan /repos/ai-monitoring --no-liveness

# every repo in the config, publishing to the bus
hygiene scan --all --publish --report-dir /var/lib/hygiene/reports

# check 3 on its own
HYGIENE_GITHUB_TOKEN=ghp_… hygiene audit-token
```

Scheduled nightly by the `hygiene-cron` compose service.

### Exit codes

| code | meaning |
|---|---|
| 0 | ran clean |
| 1 | ran, found something at or above `--fail-on` |
| 2 | **did not run correctly** — a check errored, or an alert was rejected |

2 is separate from 1 on purpose. A scheduler that treats "found secrets" and
"the scanner is broken" as one signal will eventually page on the wrong one,
and the broken scanner is the more urgent of the two. The same principle runs
through the code: a check that failed is recorded as an error, never as an
absence of findings, and the report says so at the top.

## The seeded fixture

```bash
python -m hygiene.demo.seed_repo /tmp/seeded-repo
hygiene scan /tmp/seeded-repo --repo-name acme/acme-service --no-liveness
```

Builds a repo with a historic leaked AWS key (committed, then deleted), a
committed `.env` holding an over-scoped PAT, a config file with an inline
database password, and a `.gitignore` that does not cover `.env`.

**No secret literal is committed to this repository.** The fixture synthesizes
every credential at run time from a fixed seed, so it is reproducible without a
credential-shaped string in AI Monitoring's own git history — and without a
`.gitleaks.toml` path allowlist that would blind our own scanner to that
directory forever.

> The AWS key ids are drawn from base32 (`[A-Z2-7]`), not `[A-Z0-9]`. This is
> not cosmetic: gitleaks' `aws-access-token` rule encodes AWS's real alphabet,
> so a key containing `0/1/8/9` falls through to `generic-api-key`. The fixture
> still "finds a secret", which is why it is easy to miss — but issuer routing,
> the AWS console URL and the STS liveness probe all go quietly dead. There is
> a test for exactly this.

## Tests

```bash
python -m pytest services/hygiene/tests -q
```

The history tests need `gitleaks` on `PATH`; they skip loudly by name rather
than passing without it. Every control in `test_acceptance.py` was verified by
mutation — removing the live→critical escalation, the masking, or the AWS
pairing regex each turns the relevant test red.
