# syntax=docker/dockerfile:1.7

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
COPY packages ./packages
COPY apps ./apps

RUN bun run --filter @signet/web build \
    && bun run --filter @signet/server build

# Fail the build if the server bundle is not self-contained. The runtime image
# below ships no node_modules, so every dependency must be either bundled or a
# Node built-in. Adding a native addon (e.g. @node-rs/argon2) breaks this and
# needs a production-install stage restored alongside it — prefer WASM or pure
# JS dependencies so the runtime image stays minimal and platform-independent.
RUN grep -oE 'from[[:space:]]*"[^"./][^"]*"' apps/server/dist/index.js \
    | grep -v '"node:' \
    | sort -u > /tmp/externals.txt \
    && if [ -s /tmp/externals.txt ]; then \
    echo "Server bundle has non-builtin externals:" && cat /tmp/externals.txt && exit 1; \
    fi

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

# Run unprivileged. The node image ships a `node` user at uid 1000.
USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1

CMD ["node", "dist/index.js"]
