# Dashboard API (apps/api) + static dashboard (apps/web/public).
# Build context must be the repo root (api/src/audit.js imports
# packages/audit via a relative path that resolves to /packages in-image).
FROM node:22-alpine AS deps
WORKDIR /app/api
COPY apps/api/package.json apps/api/package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app/api
COPY --from=deps /app/api/node_modules ./node_modules
COPY apps/api/package.json ./
COPY apps/api/src ./src
COPY apps/web/public /app/web/public
COPY packages/audit/package.json /packages/audit/package.json
COPY packages/audit/src /packages/audit/src
# Alert bus contract: /api/alerts validates every entry it reads
# against this file. Without it in the image the reader rejects everything and
# the inbox reads as "no alerts" — the silent drop D3.1 exists to prevent.
COPY packages/schema/schema /packages/schema/schema
# Live guardrail policy for GET /api/guardrail/rules — the same
# files the guardrail engine image loads, so the rules viewer cannot drift.
COPY policies/guardrail /app/policies/guardrail
ENV GUARDRAIL_POLICY_PATH=/app/policies/guardrail/v1
# Declared endpoint enforcement bundle for GET /api/enforcement/rules.
# Same JSON fleet tooling seeds as collectors/claude-code default_enforcement.json.
COPY deploy/enforcement /app/enforcement
ENV AIM_ENFORCEMENT_FILE=/app/enforcement/enforcement.enforce.json
# Compliance framework map for GET /api/compliance/report — same
# no-drift principle: read from disk on every request.
COPY policies/compliance /app/policies/compliance
ENV COMPLIANCE_MAP_PATH=/app/policies/compliance/framework-map.yaml
# Immutable audit trail: a writable data dir for AUDIT_LOG_PATH, owned
# by the unprivileged runtime user (the log writer does not create parents). A
# named volume mounts here in compose so the hash-chained log survives
# container recreation; the enroll-token mint/revoke records land here.
RUN mkdir -p /app/data && chown -R node:node /app/data
USER node
EXPOSE 8080
# Read-only dashboard API: the events schema is owned and migrated by the
# ingest service (services/ingest). Requires DATABASE_URL at runtime.
CMD ["node", "src/server.js"]
