# Terraform — AI Monitoring platform infrastructure

Skeleton only. **Nothing is applied.** Environments come online deliberately,
after the state backend is bootstrapped and access is reviewed.

## Layout

- `modules/network` — VPC with private subnets + DB subnet group. No public
  subnets until something actually needs inbound internet access.
- `modules/postgres` — RDS PostgreSQL with secure defaults (private, encrypted,
  generated master password in Secrets Manager, backups, deletion protection).
- `environments/dev` — first environment wiring the modules together.
- `environments/prod` — production twin (separate state key, stricter secret outputs).

## State backend

State lives in an S3 bucket with native lockfile (`use_lockfile`), encryption
at rest, and versioning. The bucket is created **once, manually** (console or
CLI) with public access fully blocked — it is intentionally not managed by
this config, because Terraform cannot create the bucket that holds its own
state without a bootstrap dance.

## Working with it

```sh
cd environments/dev   # or environments/prod
terraform init        # needs AWS creds with access to the state bucket
terraform plan        # read-only review
terraform apply       # requires explicit approval; never apply prod without change review
```

**Apply status:** modules validate in CI; no cloud account credentials are
configured in this workspace yet, so `apply` is intentionally not run here.
Track the first live dev apply as a follow-up once the state bucket and AWS
SSO role exist.

No Terraform? Use the docker targets instead:

```sh
make tf-fmt       # terraform fmt -check -recursive
make tf-validate  # init -backend=false + validate for dev
```

## Policy guardrails (before first apply)

- [ ] State bucket created with versioning + public access block.
- [ ] CI runs `fmt -check` and `validate` on every PR (done — see `.github/workflows/ci.yml`).
- [ ] `plan` output reviewed in PR before any `apply`.
- [ ] No long-lived AWS credentials on laptops — SSO/short-lived only.
