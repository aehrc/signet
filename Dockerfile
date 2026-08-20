# syntax=docker/dockerfile:1.7

# Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
# (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.

# ---------------------------------------------------------------------------
# Build stage: install the full workspace and produce both bundles.
# ---------------------------------------------------------------------------
FROM oven/bun:1-debian AS build
WORKDIR /app

# Manifests first, so a source-only change does not invalidate the install layer.
COPY package.json bun.lock ./
COPY apps/server/package.json ./apps/server/
COPY apps/web/package.json ./apps/web/
COPY packages/core/package.json ./packages/core/
COPY packages/contracts/package.json ./packages/contracts/
COPY packages/db/package.json ./packages/db/
COPY e2e/package.json ./e2e/
RUN bun install --frozen-lockfile

COPY tsconfig.base.json tsconfig.json ./
COPY scripts ./scripts
COPY packages ./packages
COPY apps ./apps

RUN bun run --filter @signet/web build \
    && bun run --filter @signet/server build

# ---------------------------------------------------------------------------
# Runtime stage.
# ---------------------------------------------------------------------------
FROM node:24-bookworm-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000 \
    SIGNET_WEB_ROOT=/app/web

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/apps/server/dist ./dist
COPY --from=build /app/apps/web/dist ./web
COPY --from=build /app/packages/db/drizzle ./drizzle

# The stack seed, so compose can run it as a service between bootstrap and
# Pathling. Pathling resolves its issuer eagerly at startup and refuses to start
# if the endpoint does not exist yet, so seeding has to happen inside the
# dependency graph rather than from the host afterwards. Plain ESM over `fetch`
# with no imports, so it runs on the runtime Node without any node_modules.
COPY --from=build /app/scripts/seedStack.mjs ./scripts/seedStack.mjs

# This image ships no node_modules, so anything left external in the bundle would
# resolve to nothing at startup. Checked here rather than in the build stage so
# `builtinModules` comes from the exact Node that will run the server - bun's
# `node` shim reports its own, slightly different, list.
COPY --from=build /app/scripts/checkBundle.mjs /tmp/checkBundle.mjs
RUN node /tmp/checkBundle.mjs dist/index.js && rm /tmp/checkBundle.mjs

# Run unprivileged. The node image ships a `node` user at uid 1000.
USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1

CMD ["node", "dist/index.js"]
