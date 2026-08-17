# Build the ingest service from the repo root:
#   docker compose build ingest
#
# ship the lockfile so install is deterministic and GHA/buildx
# cache keys stay stable across matrix publishes. --frozen-lockfile fails
# closed if package.json and pnpm-lock.yaml drift (prefer that over a
# surprise resolution that only reproduces on the sole aim-ops runner).
FROM node:22-alpine AS build
WORKDIR /repo
RUN corepack enable
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY services/ingest ./services/ingest
# Canonical event schema is bundled into the runtime image (see SCHEMA_PATH below).
COPY packages/schema/schema ./packages/schema/schema
RUN pnpm install --frozen-lockfile --filter @aimon/ingest...
RUN pnpm --filter @aimon/ingest... build
# Produce an isolated production bundle: dist + production node_modules only,
# no devDependencies (vitest/esbuild/typescript carry CVEs) and no pnpm store.
RUN pnpm --filter @aimon/ingest deploy --prod /prod

FROM node:22-alpine
ENV NODE_ENV=production
# Runtime executes `node dist/index.js` and never needs npm. Removing the base
# image's bundled npm drops its CVE surface (e.g. the vulnerable `tar` shipped
# inside npm) and shrinks the attack surface.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
WORKDIR /app
# Production bundle: dist/ + production node_modules + package.json.
COPY --from=build /prod ./
# Canonical event schema, read at runtime. Pinned via SCHEMA_PATH so it does not
# depend on the repo-relative layout the source falls back to.
COPY --from=build /repo/packages/schema/schema ./schema
ENV SCHEMA_PATH=/app/schema/v1/ai-usage-event.schema.json
USER node
EXPOSE 8080
CMD ["node", "dist/index.js"]
