.PHONY: help setup ensure-dev-env demo-stack demo-stack-preflight install-pilot install-pilot-pull install-pilot-build install-pilot-preflight dev down logs test lint typecheck build sbom tf-fmt tf-validate clean aim-cli decision-latency dpia-export dpia-check works-council-pack-check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: ## One-time dev setup: install deps + git hooks
	pnpm install
	git config core.hooksPath .githooks
	@$(MAKE) ensure-dev-env
	@echo "Git hooks path set to .githooks"

# mint stack-owned secrets into gitignored .env (dogfood `stack init`
# parity). Compose already interpolates ${GATEHOUSE_WEBHOOK_SECRET:-}; without
# a value gatehouse fails closed and crash-loops. Never hardcode the secret.
ensure-dev-env: ## Mint missing local-dev secrets into .env (gitignored, 0600)
	python3 scripts/ensure_dev_env.py

# external-ready one-command self-host / demo path
# (preflight + mint env + compose up + health + optional seed).
demo-stack: ## Self-host demo: one-command stack up + health + seed
	./scripts/demo-stack-up.sh

demo-stack-preflight: ## Self-host demo preflight only (Docker / ports / env)
	./scripts/demo-stack-up.sh --preflight-only

# pilot control plane — prefer prebuilt GHCR images (see docs/deployment/prebuilt-images.md)
install-pilot: ## Pilot install (prefer-pull; falls back to source build)
	./scripts/install-pilot.sh

install-pilot-pull: ## Pilot install requiring prebuilt images (AIM_IMAGE_TAG or pin file)
	./scripts/install-pilot.sh --pull

install-pilot-build: ## Pilot install from source (contributor path)
	./scripts/install-pilot.sh --build

install-pilot-preflight: ## Pilot preflight only (Docker / ports / disk)
	./scripts/install-pilot.sh --preflight-only

dev: ensure-dev-env ## Bring up the local stack (Postgres + MinIO + ingest + guardrail + api)
	docker compose up --build

down: ## Tear down the local stack
	docker compose down

logs: ## Tail local stack logs
	docker compose logs -f

lint: ## Lint + format check
	pnpm lint

typecheck: ## Typecheck all workspaces
	pnpm typecheck

test: ## Run unit tests
	pnpm test

decision-latency: ## Endpoint enforce-decision latency SLO (p95 < 200ms)
	python3 scripts/endpoint_decision_latency.py --check --markdown

build: ## Build all workspaces
	pnpm build

aim-cli: ## Build the packaged `aim` CLI wheel + sdist (stdlib only, offline)
	python3 scripts/build_aim_cli.py

sbom: ## Generate a CycloneDX SBOM (sbom.json) via cdxgen
	pnpm sbom

tf-fmt: ## terraform fmt -check (via docker)
	docker run --rm -v "$(CURDIR)/infra/terraform:/tf" -w /tf hashicorp/terraform:1.10 fmt -check -recursive

tf-validate: ## terraform validate for dev + prod (via docker, no backend)
	docker run --rm --entrypoint sh -v "$(CURDIR)/infra/terraform:/tf" -w /tf/environments/dev hashicorp/terraform:1.10 -c "terraform init -backend=false -input=false && terraform validate"
	docker run --rm --entrypoint sh -v "$(CURDIR)/infra/terraform:/tf" -w /tf/environments/prod hashicorp/terraform:1.10 -c "terraform init -backend=false -input=false && terraform validate"

clean: ## Remove build output and local volumes
	pnpm -r exec rm -rf dist || true
	docker compose down -v

docker-cleanup: ## Reclaim Docker disk (keep 2 newest tags/repo; safe for running stacks)
	./scripts/docker-disk-cleanup.sh
