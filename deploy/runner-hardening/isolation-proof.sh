#!/usr/bin/env bash
set -euo pipefail
echo "===== D-C2 isolation proof $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="

PG_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' stack-aim-postgres-1 | awk '{print $1}')
REDIS_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' stack-aim-redis-bus-1 | awk '{print $NF}')
MINIO_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' stack-aim-minio-1 | awk '{print $1}')
echo "Targets: postgres=$PG_IP:5432 redis=$REDIS_IP:6379 minio=$MINIO_IP:9000"

# Ensure networks
docker network inspect aim-ci-isolated >/dev/null 2>&1 || docker network create --internal --label aim.role=ci-isolated aim-ci-isolated
docker network inspect aim-ci-jobs >/dev/null 2>&1 || docker network create --label aim.role=ci-jobs aim-ci-jobs

echo
echo "### AC2: docker inspect of job container (no socket, non-root)"
# Run a long-lived inspect target briefly
CID=$(docker run -d --name aim308-proof-$$ --user 10000:10000 \
  --network aim-ci-isolated \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  alpine:3.20 sleep 30)
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT

echo "\$ docker inspect $CID --format mounts/user/network"
docker inspect "$CID" --format 'User={{.Config.User}}
NetworkMode={{.HostConfig.NetworkMode}}
Privileged={{.HostConfig.Privileged}}
Binds={{json .HostConfig.Binds}}
Mounts={{json .Mounts}}
CapDrop={{json .HostConfig.CapDrop}}
ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}}
SecurityOpt={{json .HostConfig.SecurityOpt}}'

echo
echo "Socket mount check (must be empty / absent):"
docker inspect "$CID" --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' | tee /dev/stderr | grep -E 'docker.sock' && echo "FAIL: socket mounted" || echo "OK: no docker.sock mount"

echo
echo "### AC1: isolation from stack (from inside job container)"
docker exec "$CID" sh -c "
  echo '\$ id'; id
  echo '\$ ls -la /var/run/docker.sock'
  ls -la /var/run/docker.sock 2>&1 || true
  echo
  echo '\$ nc -zv $PG_IP 5432  (stack postgres)'
  nc -zv -w 2 $PG_IP 5432 2>&1 || true
  echo '\$ nc -zv $REDIS_IP 6379  (redis bus)'
  nc -zv -w 2 $REDIS_IP 6379 2>&1 || true
  echo '\$ nc -zv $MINIO_IP 9000  (minio)'
  nc -zv -w 2 $MINIO_IP 9000 2>&1 || true
"

echo
echo "### AC3: egress — internal network (deny by default)"
echo "Allowlist (aim-ci-isolated is --internal; no external routes):"
echo "  allowed: none (default deny)"
echo "  blocked: * (including package registries until proxy path is used)"
docker exec "$CID" sh -c '
  echo "\$ wget -T 3 -qO- https://example.com"
  wget -T 3 -qO- https://example.com 2>&1 | head -c 200 || true
  echo
  echo "\$ wget -T 3 -qO- https://registry.npmjs.org/"
  wget -T 3 -qO- https://registry.npmjs.org/ 2>&1 | head -c 200 || true
  echo
  echo "\$ wget -T 3 -qO- https://pypi.org/"
  wget -T 3 -qO- https://pypi.org/ 2>&1 | head -c 200 || true
'

echo
echo "### AC3b: jobs network with egress (stack still blocked; public allowed)"
CID2=$(docker run -d --name aim308-proof2-$$ --user 10000:10000 \
  --network aim-ci-jobs \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  alpine:3.20 sleep 30)
docker exec "$CID2" sh -c "
  echo '\$ id'; id
  echo '\$ nc -zv $PG_IP 5432'
  nc -zv -w 2 $PG_IP 5432 2>&1 || true
  echo '\$ nc -zv $REDIS_IP 6379'
  nc -zv -w 2 $REDIS_IP 6379 2>&1 || true
  echo '\$ wget -T 5 -qO- https://example.com | head -c 80'
  wget -T 5 -qO- https://example.com 2>&1 | head -c 80 || true
  echo
"
docker rm -f "$CID2" >/dev/null

echo
echo "### Network configs"
docker network inspect aim-ci-isolated --format 'name={{.Name}} internal={{.Internal}} labels={{json .Labels}}'
docker network inspect aim-ci-jobs --format 'name={{.Name}} internal={{.Internal}} labels={{json .Labels}}'

echo
echo "===== END PROOF ====="
