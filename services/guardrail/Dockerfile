# Build the guardrail evaluator image from the repo root:
#   docker compose build guardrail
#
# Runs the post-ingest guardrail poller: evaluate-db on an interval.
FROM python:3.12-slim AS build
WORKDIR /src
COPY services/guardrail/pyproject.toml ./
COPY services/guardrail/src ./src
# Install the package + pinned runtime deps (PyYAML + psycopg[binary]) into an
# isolated prefix we copy into the runtime stage — keeps build tooling out.
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY --from=build /install /usr/local
# Versioned policy ruleset, read at runtime. Content is a Security-reviewed
# proposal (policies/guardrail/README) — changes go through PR review, not the
# image. Pinned here so the path does not depend on the repo-relative layout.
COPY policies/guardrail /app/policies/guardrail
# Alert bus contract. Every publish is validated against this file
# before it reaches the stream, so it ships in the image and is pointed at
# explicitly — the repo-relative fallback in bus.load_validator() resolves to
# nothing here, and a publisher that silently stopped validating is exactly
# the failure this contract is built to prevent.
COPY packages/schema/schema/v1/security-alert.schema.json /app/schema/security-alert.schema.json
ENV SECURITY_ALERT_SCHEMA_PATH=/app/schema/security-alert.schema.json
WORKDIR /app
# Drop root.
RUN useradd --system --uid 10001 --no-create-home guardrail
USER guardrail
# Poll mode serves /healthz + /readyz for k8s probes (GUARDRAIL_HEALTH_PORT).
EXPOSE 8090
# `python -m guardrail.cli poll --rules ...` — DATABASE_URL + GUARDRAIL_POLL_INTERVAL
# come from the environment (see docker-compose.yml / .env.example).
ENTRYPOINT ["python", "-m", "guardrail.cli"]
CMD ["poll", "--rules", "/app/policies/guardrail/v1"]
