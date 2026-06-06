#!/usr/bin/env node
import { FastMCP } from 'fastmcp';
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

  // Identity-gateway passthrough. When traffic flows through a trusted
  // identity gateway (Cloudflare Access, Cognito, Auth0, etc.) the gateway
  // injects a signed JWT in a configured header — verify it and attach the
  // resulting Identity to the FastMCP session so per-tool role enforcement
  // can read it via context.session.identity. No-op for stdio transport and
  // for deployments that haven't configured an identity provider.
  const server = new FastMCP({
    name: config.server.name,
    version: VERSION,
    authenticate: identityAuthenticate,
  });

  registerTools(server);

  if (transportType === 'stdio') {
    server.start({ transportType });
  } else if (transportType === 'stream') {
    server.start({
      transportType: 'httpStream',
      httpStream: {
        port: config.server.port,
        host: config.server.host,
      },
    });
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
