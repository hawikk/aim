#!/usr/bin/env bash
# AIM-308 / D-C2: create the CI job networks used by isolated PR jobs.
# Safe to re-run. Does not require root.
set -euo pipefail

create_net() {
  local name="$1" internal="$2"
  if docker network inspect "$name" >/dev/null 2>&1; then
    echo "network $name already exists"
    docker network inspect "$name" --format '  internal={{.Internal}} id={{.Id}}'
    return 0
  fi
  if [[ "$internal" == "true" ]]; then
    docker network create --internal --label aim.role=ci-isolated --label aim.ticket=AIM-308 "$name"
  else
    docker network create --label aim.role=ci-jobs --label aim.ticket=AIM-308 "$name"
  fi
  echo "created $name (internal=$internal)"
}

create_net aim-ci-isolated true
create_net aim-ci-jobs false

echo
echo "Egress allowlist policy (enforced when job uses --network aim-ci-isolated):"
echo "  default: DENY all"
echo "  allow:   none (use aim-ci-jobs only for trusted package fetches, still stack-isolated)"
echo "  never:   stack Docker networks, Postgres, MinIO, Redis bus, IdP, docker.sock"
