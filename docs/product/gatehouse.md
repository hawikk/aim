# Gatehouse — free PR-security pillar

**Positioning (deliberate):** Gatehouse is a **free / open-source PR-security
pillar** of the AI Monitoring stack. It is **not** a CI/CD product and we do not
sell it as one.

Audience: security engineers, platform owners, and external evaluators deciding
whether to install the GitHub App. Operator detail (permissions threat model,
retention, AI reviewer) lives in `docs/gatehouse-github-app.md`.

| | |
|---|---|
| **What it is** | Diff-scoped orchestration of four open scanners into **one check**, **one comment**, optional suppressions, and the shared alert bus |
| **What it is not** | A Semgrep / Snyk / GHAS replacement war, or our Actions runner mesh |
| **Edge** | IaC findings map to **CNAPP rule IDs**; same `security.alert/v1.1` bus as AIM |
| **Price** | Free pillar of the stack (personal, OSS, and enterprise installs) |
| **Code** | `services/gatehouse/` |

---

## 1. What Gatehouse is

Gatehouse is a **GitHub App + CLI** that reviews **the lines a pull request
changed** and turns four mature open scanners into a single developer-facing
signal:

| Scanner | Role |
|---|---|
| **Semgrep** | SAST on changed code (vendored rules by default; air-gapped safe) |
| **Gitleaks** | Secrets / credentials on added lines |
| **Checkov** | Infrastructure-as-code (Terraform, K8s manifests, …) |
| **Trivy** | Dependency / filesystem vulnerabilities on touched lockfiles and images |

### What you get on every PR

1. **One check run** — conclusion, summary, inline annotations (not four
   competing status checks).
2. **One sticky comment** — edited in place (`<!-- gatehouse:v1 -->`); clean PRs
   stay quiet; fixed PRs get an all-clear edit instead of a graveyard of stale
   comments.
3. **`.gatehouse.yml` suppressions** — read from the **base branch** only
   (so a PR cannot introduce a finding *and* its own mute). `reason` is required;
   suppressed findings still appear in the summary and on the alert bus as
   `status: suppressed`.
4. **Alert bus publish** — every finding (and lifecycle change) as
   `security.alert/v1.1` on the same stream AIM, the CNAPP, and Sentinel
   already consume.

Diff scope is merge-base aware: pre-existing findings on lines you did not touch
do not fail *your* PR. Re-pushes rescan only changed blobs (blob-SHA cache).

Optional add-ons (advisory by default): AI second-opinion over the same diff,
and one-click suggested fixes for a reviewed catalogue of patches. Neither is
required to use Gatehouse as a PR gate.

---

## 2. What Gatehouse is not

Be precise when evaluating or marketing this pillar.

### Not a scanner-replacement war

Gatehouse **orchestrates** Semgrep, Gitleaks, Checkov, and Trivy. It is an
honest **wrapper / unifier**, not a claim that we out-detect GitHub Advanced
Security, Semgrep App, or Snyk Code on every rule.

- If you already pay for GHAS Code Scanning, Semgrep Cloud, or Snyk Code, keep
  them where they earn their keep (deep rule packs, org-wide dashboards, auto-fix
  product lines).
- Gatehouse’s job is **one PR surface**, **least-privilege App install**,
  **diff-scoped signal**, and **stack integration** (CNAPP map + shared alert
  bus) — not “uninstall your SAST vendor.”

### Not our Actions runner mesh

Gatehouse is **not** the product’s self-hosted Actions capacity, CI queue
hygiene, or merge-bot infrastructure.

| Concern | Owns it | Not Gatehouse |
|---|---|---|
| PR webhook → scanners → check/comment/bus | **Gatehouse** | |
| `aim-ci` / `aim-ops` runner labels, isolation, zero-hosted-minutes policy | PR security **runner** ops (`docs/security/pr-security-runner.md`) | Gatehouse does not sell or operate a public CI fleet |
| Required-check lists, auto-merge, audited bypass | Merge control (`docs/security/enforcing-ci-gates.md`) | Repo admins own branch protection; Gatehouse only emits a check |
| Full-history secret hygiene | **hygiene** pillar | Gatehouse is worktree / PR-diff only |

Customers install Gatehouse as an App (or run the CLI). They do **not** buy a
“CI/CD platform” from us.

### Not a CI/CD product

Do **not** describe Gatehouse as:

- a CI/CD platform, pipeline product, or Actions alternative  
- “CI/CD-native security” as a standalone pitch  
- a replacement for GitHub Actions, GitLab CI, Buildkite, etc.

Correct framing: **PR-time security review** inside whatever SCM workflow you
already have. The App uses GitHub’s check-run and comment APIs; the CLI can run
as one step in any existing pipeline without becoming the pipeline.

---

## 3. The real edge: CNAPP rule IDs + shared alert bus

Most PR scanners stop at “Checkov said `CKV_AWS_20`.” Gatehouse’s differentiator
inside this stack is **semantic continuity from IaC at merge time to cloud
posture after deploy**.

### IaC → CNAPP parity

- Checkov (and mapped) IaC findings are enriched with **CNAPP rule IDs** from a
  vendored posture catalog and mapping
  (`services/gatehouse/src/gatehouse/cnapp_parity/`).
- The PR comment includes a **“Would-be cloud findings”** section when a mapped
  misconfiguration is in scope — same rule family the CNAPP would open
  post-apply (for example public S3 / open security groups).
- Drift between the map and the catalog fails closed in CI
  (`gatehouse iac-parity`). See `docs/security/iac-cnapp-parity.md`.

That is the product edge worth saying out loud: **pre-merge gate on the same
rule semantics the CNAPP enforces post-deploy** — not a disconnected scanner id
soup.

### Same alert bus as AIM

Findings publish as `security.alert/v1.1` with lifecycle
`new → updated → suppressed → resolved`. Consumers (Sentinel SIEM path, inbox,
correlation) do not need a second integration just because the finding came from
a PR instead of an AI guardrail or cloud posture scan. Schema contract:
`packages/schema` (`security-alert.schema.json`).

---

## 4. Install / enable (GitHub App, least privilege)

Suitable for external readers. Full permission threat model:
`docs/gatehouse-github-app.md` §1. Manifest source of
truth: [`services/gatehouse/app-manifest.yml`](../../services/gatehouse/app-manifest.yml).

### Permissions (exactly three)

| Permission | Level | Why |
|---|---|---|
| `contents` | **read** | Ephemeral clone of the PR head; read `.gatehouse.yml` from the **base** branch |
| `pull_requests` | **write** | Post/edit the single summary comment (GitHub’s minimum for commenting) |
| `checks` | **write** | Create the check run, conclusion, annotations |

**No** org admin, members, Actions, or repository administration. Subscribed
event: **`pull_request` only** (`opened`, `synchronize`, `reopened`,
`ready_for_review`).

Runtime tokens are scoped to **one repository** and those three permissions,
held in process memory only, never logged, never written to disk.

### Enable path (external / self-hosted)

1. **Deploy the service** (compose service `gatehouse`, or your own container
   from this repo). Set at minimum:
   - `GATEHOUSE_APP_ID`, `GATEHOUSE_PRIVATE_KEY` (or path)
   - `GATEHOUSE_WEBHOOK_SECRET`
   - alert bus URL if you want stack integration
2. **Create the GitHub App from the manifest**  
   GitHub → Settings → Developer settings → GitHub Apps → *New GitHub App* →
   *from a manifest* → paste/upload `services/gatehouse/app-manifest.yml`.  
   Point `hook_attributes.url` at your public webhook endpoint
   (`https://<host>/webhook`).
3. **Install the App** on the target org or selected repositories (least
   privilege: only repos that should be gated).
4. **(Optional) Require the check** in branch protection / rulesets so the
   check conclusion can block merge. Gatehouse cannot set branch protection
   itself — that stays with repo admins.
5. **(Optional) Drop `.gatehouse.yml`** on the default branch for suppressions,
   scanner toggles, and `enforcement.block_on`.

### CLI without GitHub (any existing pipeline)

```bash
docker compose build gatehouse
docker run --rm -v "$PWD":/repo:ro gatehouse:dev \
  scan --repo-dir /repo --repo-name owner/name --pr 0 --base origin/main
```

Exit code `1` when something blocks, `0` otherwise. Use as a single step in
Jenkins, GitLab CI, Buildkite, etc. — still not “buying our CI.”

### What Gatehouse never does

- Push commits, open fix PRs under the PR App identity (remediation is
  suggestion / copy-paste; a separate least-privilege remediation App exists
  for draft PRs where policy allows).
- Store source code after the run (ephemeral workspace, deleted in `finally`).
- Publish raw secret values or author identity on the alert bus.

---

## 5. Comparison (honest wrapper design)

Gatehouse is a **wrapper + stack bridge**. Compare on that basis.

| | **Gatehouse** | **GitHub Advanced Security (GHAS)** | **Semgrep App / Cloud** | **Snyk Code** |
|---|---|---|---|---|
| Primary product | Free PR-security **pillar** of AIM + CNAPP stack | GitHub-native code scanning, secret scanning, Dependabot | SAST platform + rule ecosystem | Developer security platform (SAST + SCA + more) |
| Scanners | Orchestrates Semgrep + Gitleaks + Checkov + Trivy | GitHub CodeQL / secret scanning / dependency graph | Semgrep engine + packs | Snyk proprietary + OSS data |
| PR UX | **One** check + **one** comment by design | Multiple checks / security tab / Dependabot alerts | PR comments + checks (product-dependent) | PR checks + fix PRs (product-dependent) |
| Diff scope | First-class merge-base added-line filter | Configurable; often broader/default full analysis | Strong PR focus | Strong PR focus |
| Suppressions | `.gatehouse.yml` on base branch; reason required; still on bus | Code scanning alert dismissals / exclude paths | `.semgrepignore` / app policies | Snyk ignores / policies |
| Cloud / CNAPP link | **Mapped CNAPP rule IDs** on IaC findings | Separate from cloud posture products | Not a CNAPP posture map | Separate cloud products (Snyk Cloud, etc.) |
| Alert integration | Same **`security.alert/v1.1`** bus as AIM | GitHub Security / webhooks / SIEM exporters | Semgrep Cloud / webhooks | Snyk reporting / integrations |
| Install surface | Least-privilege **3-permission** App or CLI | Org GHAS entitlement + repo enablement | Semgrep App or CLI | Snyk App / CLI / SCM integration |
| Best fit | Teams that want **one PR gate** wired into **this stack** without a scanner bake-off | Orgs standardized on GitHub Security | Teams deep in Semgrep rules / supply chain | Teams deep in Snyk portfolio |
| Honest limit | Does not invent a fifth engine; depth = upstream tools + our map/bus | Best when you want GitHub-native depth and are already paying | Best pure SAST experience | Best when Snyk is already the security system of record |

**Takeaway for buyers:** use Gatehouse when the value is **unified PR signal +
CNAPP continuity + shared AIM alert bus**. Keep or buy GHAS / Semgrep / Snyk
when you need their depth, org dashboards, or contractual coverage. Running both
is normal; Gatehouse is not positioned as “rip and replace.”

---

## Where to go next

| Need | Doc |
|---|---|
| Stack placement (pillars, free vs paid) | [stack-overview.md](./stack-overview.md) |
| Service layout & local scan | [`services/gatehouse/README.md`](../../services/gatehouse/README.md) |

*Document status: product positioning. Policy
thresholds remain Security/Legal; this page describes mechanism and market
framing only.*
