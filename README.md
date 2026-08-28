[![License](https://img.shields.io/github/license/cswkim/discogs-mcp-server)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/cswkim/discogs-mcp-server)](https://github.com/cswkim/discogs-mcp-server/releases)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/cswkim/discogs-mcp-server/.github%2Fworkflows%2Fcheck-pr.yml)](https://github.com/cswkim/discogs-mcp-server/actions/workflows/check-pr.yml)
[![NPM Downloads](https://img.shields.io/npm/d18m/discogs-mcp-server)](https://www.npmjs.com/package/discogs-mcp-server)
[![Sponsor](https://img.shields.io/static/v1?label=sponsor&message=%E2%9D%A4&logo=GitHub&color=ff69b4)](https://github.com/sponsors/cswkim)

# Discogs MCP Server

MCP Server for the Discogs API, enabling music catalog operations, search functionality, and more.

## Quickstart

If you just want to get started immediately using this MCP Server with the [Claude](https://claude.ai) desktop app and don't care about development or running the server yourself, then make sure you have [Node.js](https://nodejs.org/en) installed and your Discogs personal access token ready and skip straight to the [Claude configuration section](#claude-desktop-configuration). Use the `NPX` method from that section.

## Table of Contents

- [Acknowledgements](#acknowledgements)
- [Available Tools](#available-tools)
- [Caveats](#caveats)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Running the Server](#running-the-server-locally)
  - [Option 1: Local Development](#option-1-local-development)
  - [Option 2: Docker](#option-2-docker)
- [Deploying to Google Cloud Run](#deploying-to-google-cloud-run)
- [Inspection](#inspection)
- [MCP Clients](#mcp-clients)
  - [Claude Desktop Configuration](#claude-desktop-configuration)
    - [NPX](#npx)
    - [Local Node](#local-node)
    - [Docker](#docker)
  - [LibreChat](#librechat)
  - [LM Studio](#lm-studio)
- [TODO](#todo)
- [License](#license)

## Acknowledgements

This MCP server is built using [FastMCP](https://github.com/punkpeye/fastmcp), a typescript framework for building MCP servers. For more information about MCP and how to use MCP servers, please refer to the [FastMCP documentation](https://github.com/punkpeye/fastmcp/blob/main/README.md) and the [official MCP documentation](https://modelcontextprotocol.io).

## Available Tools

Check out the list of available tools: [TOOLS.md](TOOLS.md)

## Caveats

- The [Discogs API documentation](https://www.discogs.com/developers) is not perfect and some endpoints may not be fully documented or may have inconsistencies.
- Due to the vast number of API endpoints and response types, it's not feasible to verify type safety for every possible response. Please report any type-related issues you encounter.
- This MCP server allows for editing data in your Discogs collection. Please use with caution and verify your actions before executing them.
- The Discogs API `per_page` default is `50`, which can be too much data for some clients to process effectively, so within this project a `discogs.config.defaultPerPage` value has been set to `5`. You can request more data in your prompts, but be aware that some clients may struggle with larger responses.

## Prerequisites

- Node.js (tested with Node.js `20.x.x`, but `18.x.x` should work as well)
  - Check your Node.js version with: `node --version`
- Docker (optional, for running a local docker image without having to deal with Node or dependencies)

## Setup

1. Clone the repository
2. Create a `.env` file in the root directory based on `.env.example`
3. Set the following required environment variables in your `.env`:
   - `DISCOGS_PERSONAL_ACCESS_TOKEN`: Your Discogs personal access token

To get your Discogs personal access token, go to your [Discogs Settings > Developers](https://www.discogs.com/settings/developers) page and find your token or generate a new one. **_DO NOT SHARE YOUR TOKEN_**. OAuth support will be added in a future release.

The other environment variables in `.env.example` are optional and have sensible defaults, so you don't need to set them unless you have specific requirements.

- `SERVER_HOST`: The host address to bind the server to (default: `0.0.0.0`). Set to `0.0.0.0` to allow connections from outside the container/machine, or `127.0.0.1` to restrict to localhost only.

## Running the Server Locally

### Option 1: Local Development

1. Install dependencies:
   ```bash
   pnpm install
   ```

2. Available commands:
   - `pnpm run dev`: Start the development server with hot reloading
   - `pnpm run dev:stream`: Start the development server with hot reloading in HTTP streaming mode
   - `pnpm run build`: Build the production version
   - `pnpm run start`: Run the production build
   - `pnpm run inspect`: Run the MCP Inspector (see [Inspection](#inspection) section)
   - `pnpm run format`: Check code formatting (prettier)
   - `pnpm run lint`: Run linter (eslint)
   - `pnpm run test`: Run vitest
   - `pnpm run test:coverage`: Run vitest v8 coverage
   - `pnpm run version:check`: Checks that the package.json version and src/version.ts match

### Option 2: Docker

1. Build the Docker image:
   ```bash
   docker build -t discogs-mcp-server:latest .
   ```

2. Run the container:
   ```bash
   docker run --env-file .env discogs-mcp-server:latest
   ```

   For HTTP Streaming transport mode:
   ```bash
   # The port should match what is in your .env file
   # By default, the server listens on 0.0.0.0, allowing connections from outside the container
   docker run --env-file .env -p 3001:3001 discogs-mcp-server:latest stream
   ```

## Deploying to Google Cloud Run

This repo ships two Cloud Build configs that auto-deploy the server to
Google Cloud Run. They follow the same dev/prod split used by
[`cellartracker-mcp-server`](https://github.com/mmmnorthmark/cellartracker-mcp)
and are designed to sit behind a Cloudflare Worker that handles edge
authentication via Cloudflare Access. See the broader
[`mcp-on-gcp`](https://github.com/mmmnorthmark/mcp-on-gcp) reference for
the topology (Worker → Cloud Run IAM → Cloud Run service → MCP server).

| File | Trigger | Cloud Run service | Image tag |
| --- | --- | --- | --- |
| `cloudbuild.yaml` | push to `main` | `discogs-mcp-dev` | `:$COMMIT_SHA`, `:latest` |
| `cloudbuild-prod.yaml` | tag matching `v*.*.*` | `discogs-mcp-server` | `:$TAG_NAME`, `:latest` |

Both configs use `gcloud run services update --image=...` (not `deploy`),
so env vars and secret refs already set on the service are preserved
across deploys.

### Cloud Run environment variables

Required:

- `DISCOGS_PERSONAL_ACCESS_TOKEN` — your Discogs token.

Recommended when serving real traffic:

- `MCP_SERVER_URL` — public URL of the service (e.g. `https://discogs-mcp.example.com`).
- `SERVER_HOST=0.0.0.0` (already the default).
- `PORT` — set automatically by Cloud Run; the server reads it.

### Identity-gateway passthrough

Only relevant if traffic reaches the server through a gateway that
injects a **signed** identity JWT. Set `IDENTITY_PROXY` to a preset and
the header plus verification defaults come with it; any explicit
`IDENTITY_*` var always overrides the preset.

| `IDENTITY_PROXY` | Header | Notes |
|---|---|---|
| `cloudflare` | `Cf-Access-Jwt-Assertion` | JWKS/issuer derived from `CF_ACCESS_TEAM_DOMAIN`; audience from `CF_ACCESS_AUD`. |
| `gcp-iap` | `X-Goog-Iap-Jwt-Assertion` | ES256 via gstatic; requires `IDENTITY_AUDIENCE` (`/projects/NUM/...`); 30s clock skew. |
| `aws-alb` | `X-Amzn-Oidc-Data` | Needs `IDENTITY_AWS_REGION`; set `IDENTITY_AWS_ALB_ARN` to verify the signer (AWS requires this). |
| `oauth2-proxy` | `X-Forwarded-Email` | **Unsigned.** Ignored unless `TRUST_UNSIGNED_PROXY_HEADERS=true`. Private networks only. |
| unset / `custom` | `Cf-Access-Jwt-Assertion` | Generic mode: supply `IDENTITY_JWKS_URL`, `IDENTITY_ISSUER`, `IDENTITY_AUDIENCE` yourself. |

Shared knobs: `IDENTITY_HEADER`, `IDENTITY_EMAIL_CLAIM` (default
`email`), `IDENTITY_GROUPS_CLAIM` (default `groups`).

> **The Cloudflare MCP portal does not forward `Cf-Access-Jwt-Assertion`
> upstream** (verified 2026-08-28). Behind a portal, none of the above
> fires — callers arrive as OAuth Bearer identities with no groups. Use
> the email tiers below, not the group lists.

### Per-tool role authorization (RBAC)

Two independent sources, either or both:

**By email** — works everywhere, including behind the MCP portal, since
it needs only the verified email:

- `IDENTITY_ROLE_ADMIN_EMAILS` — comma-separated emails mapping to `admin`.
- `IDENTITY_ROLE_WRITER_EMAILS` — emails mapping to `writer`.
- `IDENTITY_ROLE_READER_EMAILS` — emails mapping to `reader`.

**By group** — requires a gateway that actually forwards group claims:

- `IDENTITY_ROLE_ADMIN_GROUPS` — comma-separated group names mapping to `admin`.
- `IDENTITY_ROLE_WRITER_GROUPS` — group names mapping to `writer`.
- `IDENTITY_ROLE_READER_GROUPS` — group names mapping to `reader`.

Matching is case-insensitive and whitespace-trimmed for both sources.
When both match, the **highest** tier wins (`admin` > `writer` >
`reader`), and a higher tier satisfies any lower requirement.

When **none** of the six lists is set, enforcement is a no-op and the
deployment behaves like a single-tenant server. Once **any** list is
set, resolution is **fail-closed**: an identity matching no list gets no
tools. Configuring only the `_GROUPS` lists behind the MCP portal
therefore locks everyone out — that is the trap the email tiers exist
to avoid.

Every tool's required role, along with its MCP annotations, comes from
the single `TOOL_RISK` table in `src/tools/toolRisk.ts`. A tool missing
from that table falls back to `UNKNOWN_TOOL_RISK` (admin + destructive),
so forgetting to classify a new tool denies access rather than granting
it.

#### Generating the roster

The Cloudflare Access `terraform.tfvars` is the authored source of who
gets which tier. Rather than hand-maintaining the env vars, generate
them:

```bash
npx tsx ~/Dropbox/Code/books-mcp-server/scripts/gen-role-env.ts \
  ~/code-local/cellartracker-mcp-gcp-deployment/infra/cloudflare-access/terraform.tfvars \
  Music
```

That prints the three `IDENTITY_ROLE_*_EMAILS` lines for this service's
`service_access.Music` entry, ready to paste into a
`gcloud run services update --update-env-vars` call.

## Inspection

Run the MCP Inspector to test your local MCP server:

```bash
pnpm run inspect
```

This will start the MCP Inspector at `http://127.0.0.1:6274`. Visit this URL in your browser to interact with your local MCP server.

For more information about the MCP Inspector, visit [the official documentation](https://modelcontextprotocol.io/docs/tools/inspector).

## MCP Clients

More client examples will be added in the future. If you'd like configuration for a specific client, either
request it by opening a new issue or creating the pull request to edit this section of the README yourself.

### Claude Desktop Configuration

Find your `claude_desktop_config.json` at `Claude > Settings > Developer > Edit Config` and depending on which option you'd like, add **JUST ONE** of the following:

#### NPX

Running it straight from the npm registry.

```json
{
  "mcpServers": {
    "discogs": {
      "command": "npx",
      "args": [
        "-y",
        "discogs-mcp-server"
      ],
      "env": {
        "DISCOGS_PERSONAL_ACCESS_TOKEN": "<YOUR_TOKEN>"
      }
    }
  }
}
```

#### Local Node

Dependencies should have been installed before you use this method (`pnpm install`).

```json
{
  "mcpServers": {
    "discogs": {
      "command": "npx",
      "args": [
        "tsx",
        "/PATH/TO/YOUR/PROJECT/FOLDER/src/index.ts"
      ],
      "env": {
        "DISCOGS_PERSONAL_ACCESS_TOKEN": "<YOUR_TOKEN>"
      }
    }
  }
}
```

#### Docker

The docker image should have been built before using this method.

```json
{
  "mcpServers": {
    "discogs": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--env-file",
        "/PATH/TO/YOUR/PROJECT/FOLDER/.env",
        "discogs-mcp-server:latest"
      ]
    }
  }
}
```

Any changes to local code will require Claude to be restarted to take effect. Also, Claude requires human-in-the-loop interaction to allow an MCP tool to be run, so everytime a new tool is accessed Claude will ask for permission. You usually only have to do this once per tool per chat. _If using the free version, long chats may result in more frequent errors trying to run tools as Claude limits the amount of context within a single chat._

### LibreChat

In the `librechat.yaml` configuration file, add this under the `mcpServers` section:

```yaml
discogs:
  type: stdio
  command: npx
  args: ["-y", "discogs-mcp-server"]
  env:
    DISCOGS_PERSONAL_ACCESS_TOKEN: YOUR_TOKEN_GOES_HERE
```

### LM Studio

Get to the Chat `Settings`. In the `Program` tab there will be a dropdown with a default of `Install`. Select `Edit mcp.json`. Add this under the `mcpServers` section:

```json
"discogs": {
  "command": "npx",
  "args": [
    "-y",
    "discogs-mcp-server"
  ],
  "env": {
    "DISCOGS_PERSONAL_ACCESS_TOKEN": "YOUR_TOKEN_GOES_HERE"
  }
}
```

After you Save, in the `Program` tab there should now be an `mcp/discogs` toggle to enable the server. Within every chat box there is an `Integrations` menu where you can also enable mcp servers.

## TODO

- OAuth support
- Missing tools:
  - Inventory uploading

## License

This MCP server is licensed under the MIT License. This means you are free to use, modify, and distribute the software, subject to the terms and conditions of the MIT License. For more details, please see the LICENSE file in the project repository.
