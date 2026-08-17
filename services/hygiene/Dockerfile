# syntax=docker/dockerfile:1
#
# Pillar 4 — secrets & token hygiene.
#
# Ships gitleaks alongside the service for the same reason gatehouse does: the
# scanner IS the behaviour, so it is versioned and pinned with the code rather
# than fetched at scan time from a network the scan cannot depend on.

FROM debian:bookworm-slim AS scanners
ARG GITLEAKS_VERSION=8.28.0
# Checksum from the project's published `*_checksums.txt`. A pinned version
# without a pinned hash is not a supply-chain control: GitHub release assets are
# mutable by whoever holds the repo, so the tag alone proves nothing. If
# upstream is tampered with, this build fails instead of shipping a backdoored
# scanner onto the box that reads every credential in the company.
ARG GITLEAKS_SHA256=a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates curl; \
    curl -fsSL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    chmod 0755 /usr/local/bin/gitleaks; \
    rm -rf /tmp/*.tar.gz /var/lib/apt/lists/*

FROM python:3.12-slim AS build
WORKDIR /src
COPY services/hygiene/pyproject.toml ./
COPY services/hygiene/src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
# git is not optional here — the whole pillar is a history scan.
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends git ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --create-home --uid 10004 hygiene

COPY --from=scanners /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=build /install /usr/local
# The alert contract, so the publisher can validate without reaching the repo.
COPY packages/schema/schema/v1/security-alert.schema.json \
     /usr/local/lib/hygiene-schema/security-alert.schema.json

ENV SECURITY_ALERT_SCHEMA_PATH=/usr/local/lib/hygiene-schema/security-alert.schema.json \
    HYGIENE_STATE_DIR=/var/lib/hygiene \
    PYTHONUNBUFFERED=1

# Findings state, the HMAC fingerprint key, and rendered reports.
RUN install -d -o hygiene -g hygiene -m 0700 /var/lib/hygiene

USER hygiene
WORKDIR /var/lib/hygiene

# No default long-running process: this is a scheduled batch job, driven by the
# `hygiene-cron` compose service or by an operator on the shell. A service that
# idles in a loop would hold a checkout open for no reason.
ENTRYPOINT ["hygiene"]
CMD ["--help"]
