#!/usr/bin/env node
import { FastMCP } from 'fastmcp';
import { isOAuthConfigured } from './auth/googleOAuthProvider.js';
import { buildFastmcpOAuthConfig, registerOAuthRoutes } from './auth/oauthRoutes.js';
import { isRbacEnabled } from './auth/roleAuthz.js';
import { identityAuthenticate } from './auth/sessionAuth.js';
import { config, validateConfig } from './config.js';
import { registerTools } from './tools/index.js';
import { log } from './utils.js';
import { VERSION } from './version.js';

type ServerTransportType = 'stdio' | 'stream';

function assertTransportType(transportType: string): transportType is ServerTransportType {
  return transportType === 'stdio' || transportType === 'stream';
}

try {
  validateConfig();

  // Grab the transport type from the command line
  const transportType = process.argv[2] ?? 'stdio';

  // Make sure the transport type is allowed
  if (!assertTransportType(transportType)) {
    throw Error(
      `Invalid transport type: "${transportType}". Allowed: 'stdio' (default) or 'stream'.`,
    );
  }

  // OAuth is enabled only when GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and
  // MCP_SERVER_URL are all set. When it is, this process is both the MCP
  // server and its own OAuth authorization server (a broker in front of
  // Google) — see src/auth/googleOAuthProvider.ts.
  const oauthEnabled = isOAuthConfigured();

  // authenticate() accepts either a trusted identity-gateway JWT (Cloudflare
  // Access, Cognito, Auth0, ...) or a Google Bearer access token validated
  // against Google's tokeninfo endpoint plus the ALLOWED_GOOGLE_EMAILS
  // allowlist. Either way it attaches an Identity to the FastMCP session so
  // per-tool role enforcement can read it via context.session.identity.
  const server = new FastMCP({
    name: config.server.name,
    version: VERSION,
    authenticate: identityAuthenticate,
    // Adds the resource_metadata hint to 401s from /mcp. The discovery
    // documents themselves are served by registerOAuthRoutes() below.
    ...(oauthEnabled ? { oauth: buildFastmcpOAuthConfig() } : {}),
  });

  registerTools(server, {
    readOnly: config.server.readOnly,
  });

  if (transportType === 'stdio') {
    server.start({ transportType });
  } else if (transportType === 'stream') {
    // The OAuth endpoints live on FastMCP's own Hono app so /authorize,
    // /token, /register, /revoke and /callback are served from the same
    // process and port as /mcp. Only meaningful over HTTP.
    if (oauthEnabled) {
      registerOAuthRoutes(server.getApp());
    } else {
      log.info('OAuth disabled - server running without an authorization server');
      log.info('  To enable, set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and MCP_SERVER_URL');
    }

    server.start({
      transportType: 'httpStream',
      httpStream: {
        port: config.server.port,
        host: config.server.host,
      },
    });
  }

  if (config.server.readOnly) {
    log.info('Read-only mode enabled: mutating tools are disabled');
  }
  if (isRbacEnabled()) {
    log.info('Per-tool RBAC enabled: tool access gated by identity group membership');
  } else {
    log.info(
      'Per-tool RBAC NOT enforced - no IDENTITY_ROLE_*_GROUPS configured; ' +
        'access is gated by ALLOWED_GOOGLE_EMAILS alone',
    );
  }
  log.info(`${config.server.name} started with transport type: ${transportType}`);
} catch (error: unknown) {
  log.error(`Failed to run the ${config.server.name}: `, error);
  process.exit(1);
}

// Handle process termination gracefully
process.on('SIGINT', () => {
  log.info('Shutting down server...');
  process.exit(0);
});
