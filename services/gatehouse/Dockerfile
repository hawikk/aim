# gatehouse — PR-time security scanner service. Build from the repo root:
#   docker compose build gatehouse
#
# The four scanners are baked into the image at pinned versions. The obvious
# alternative — mounting the Docker socket and running each scanner as its own
# container — was rejected: the socket is root on the host, and this is the one
# service in the stack that clones and executes analysis over *untrusted* code.
# Trading a container escape surface for a smaller image is a bad trade here.
#
# Pinning is the supply-chain control. Scanner versions move on their own
# schedule; an unpinned `latest` means the gate's behaviour changes without a
# commit, and a compromised upstream release lands automatically.
FROM python:3.12-slim AS scanners
ARG GITLEAKS_VERSION=8.28.0
ARG TRIVY_VERSION=0.72.0
# Checksums from each project's published `*_checksums.txt`. A pinned version
# without a pinned hash is not a supply-chain control: GitHub release assets
# are mutable by whoever holds the repo, so the tag alone proves nothing. If
# either upstream is tampered with, this build fails instead of shipping a
# backdoored scanner into a service that reads every PR in the company.
ARG GITLEAKS_SHA256=a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb
ARG TRIVY_SHA256=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates curl; \
    curl -fsSL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    curl -fsSL -o /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    chmod 0755 /usr/local/bin/gitleaks /usr/local/bin/trivy; \
    rm -rf /tmp/*.tar.gz /var/lib/apt/lists/*

FROM python:3.12-slim AS build
WORKDIR /src
COPY services/gatehouse/pyproject.toml ./
COPY services/gatehouse/src ./src
# semgrep and checkov are Python tools; installing them into the same prefix as
# gatehouse keeps one runtime layer instead of three.
RUN pip install --no-cache-dir --prefix=/install . \
    "semgrep==1.171.0" "checkov==3.3.8"

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SEMGREP_SEND_METRICS=off \
    DO_NOT_TRACK=1 \
    TRIVY_CACHE_DIR=/opt/trivy-cache \
    GATEHOUSE_STATE_DB=/var/lib/gatehouse/state.db
# git is the only runtime tool beyond the scanners: the ephemeral checkout is a
# partial clone (workspace.py), which needs a real git, not a tarball fetch.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /install /usr/local
COPY --from=scanners /usr/local/bin/gitleaks /usr/local/bin/trivy /usr/local/bin/
# Alert bus contract — every publish is validated against this file
# before it reaches the stream. Shipped in the image and pointed at explicitly,
# because bus.load_validator() returning None is treated as a rejection.
COPY packages/schema/schema/v1/security-alert.schema.json /app/schema/security-alert.schema.json
ENV SECURITY_ALERT_SCHEMA_PATH=/app/schema/security-alert.schema.json

# Bake the trivy vulnerability DB so scans run with --skip-db-update. Without
# this, every cold start downloads ~40 MB from GHCR before the first scan can
# finish, and an air-gapped install (D6) silently scans nothing.
RUN trivy image --download-db-only --cache-dir "$TRIVY_CACHE_DIR" \
    && chmod -R a+rX "$TRIVY_CACHE_DIR"

RUN useradd --system --uid 10001 --no-create-home gatehouse \
    && mkdir -p /var/lib/gatehouse /tmp/gatehouse \
    && chown gatehouse:gatehouse /var/lib/gatehouse /tmp/gatehouse
WORKDIR /app
USER gatehouse
EXPOSE 8090
ENTRYPOINT ["python", "-m", "gatehouse.cli"]
CMD ["serve"]
