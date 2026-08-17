# sentinel — bus consumer, triage, notification. Build from the repo root:
#   docker compose build sentinel
#
# Small on purpose. This is the one service that talks to an external LLM
# endpoint and to Slack, so the list of things inside the image that can open a
# socket is a security property: python, three pure-python libraries, and no
# cloud SDK anywhere (D4 — the agent holds no write credentials and has nothing
# installed that could use one).
FROM python:3.12-slim AS build
WORKDIR /src
COPY services/sentinel/pyproject.toml ./
COPY services/sentinel/src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SENTINEL_STATE_DB=/var/lib/sentinel/state.db \
    SECURITY_ALERT_SCHEMA_DIR=/app/schema
COPY --from=build /install /usr/local

# Both halves of the alert contract (D3.1 §6.1). The consumer profile is what
# entries are validated against; the strict publisher schema is the projection
# map. A missing file here makes every alert fail validation — which reads
# exactly like a quiet bus — so bus.Contract() raises at construction rather
# than letting the service come up healthy and deaf.
COPY packages/schema/schema/v1/security-alert.consumer.schema.json \
     packages/schema/schema/v1/security-alert.schema.json /app/schema/

RUN useradd --system --uid 10002 --no-create-home sentinel \
    && mkdir -p /var/lib/sentinel \
    && chown sentinel:sentinel /var/lib/sentinel
WORKDIR /app
USER sentinel
EXPOSE 8091
ENTRYPOINT ["python", "-m", "sentinel.cli"]
CMD ["serve"]
