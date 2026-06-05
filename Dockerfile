# Multi-stage build for Cloud Run.
#
# The project is pnpm-managed (pnpm-lock.yaml). Using `npm install` here
# would silently regenerate the lockfile and drift from local/CI versions,
# so this image uses corepack to install pnpm and runs
# `pnpm install --frozen-lockfile`.
#
# Cloud Run sets PORT (default 8080) at runtime. The discogs MCP server's
# stream transport reads it via config.server.port (process.env.PORT). The
# default CMD starts the server with `stream` (HTTP) so Cloud Run can
# health-check and route traffic; stdio mode would block on stdin and
# fail readiness.

FROM node:22.12-alpine AS builder

WORKDIR /app

# corepack ships with Node 22 and resolves a pnpm version from
# package.json's `packageManager` field (or falls back to its bundled
# default). Enable here so `pnpm` is on PATH for both install + build.
RUN corepack enable

# Install git for the dotenv GitHub dependency declared in package.json.
RUN apk add --no-cache git

# Copy lockfile + manifest first so the install layer caches across
# source changes. tsconfig + tsup config are needed for the build below.
COPY package.json pnpm-lock.yaml ./
COPY tsconfig.json ./
COPY tsup.config.ts ./

RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

COPY src ./src

RUN pnpm run build

# ---------------------------------------------------------------------------
# Release stage: copy built artifacts + install production deps only.
# ---------------------------------------------------------------------------
FROM node:22.12-alpine AS release

WORKDIR /app

RUN corepack enable

# tini gives us a real PID 1 — clean signal handling on SIGTERM (which
# Cloud Run sends on scale-down or revision change). git is still needed
# at runtime because the dotenv GitHub dep is resolved by pnpm install
# below.
RUN apk add --no-cache git tini

COPY --from=builder /app/dist /app/dist
COPY --from=builder /app/package.json /app/package.json
COPY --from=builder /app/pnpm-lock.yaml /app/pnpm-lock.yaml

ENV NODE_ENV=production

RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --prod --ignore-scripts

# Run as the unprivileged `node` user shipped in the base image.
USER node

# Cloud Run will overwrite PORT at runtime; the default here lets
# `docker run` (no -e PORT) behave the same locally.
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/sbin/tini", "--", "node", "dist/index.js"]
CMD ["stream"]
