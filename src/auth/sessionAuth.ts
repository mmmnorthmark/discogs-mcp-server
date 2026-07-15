/**
 * FastMCP authentication adapter — two accepted identity paths.
 *
 * 1. Identity gateway (wins when present). When traffic flows through a
 *    trusted gateway (Cloudflare Access, Cognito, Auth0, etc.) the gateway
 *    injects a signed JWT in a configured header; we verify it and attach
 *    the resulting Identity to the session. The gateway has already gated
 *    the request against its own policy, so ALLOWED_GOOGLE_EMAILS is not
 *    consulted for these requests.
 *
 * 2. Google Bearer access token. Tokens minted by this server's own OAuth
 *    authorization server (src/auth/googleOAuthProvider.ts) are Google's
 *    access tokens passed through, so they are validated against Google's
 *    tokeninfo endpoint and then gated by the ALLOWED_GOOGLE_EMAILS
 *    allowlist. This is the path MCP clients take when there is no gateway
 *    in front of the server.
 *
 * Requests with neither a gateway JWT nor a Bearer token return `undefined`
 * so FastMCP still serves them without an identity — whether that is
 * rejected is the job of roleAuthz (RBAC) when configured, or of the
 * platform fronting this service. A Bearer token that IS present but fails
 * validation is a hard 401: silently downgrading a bad token to anonymous
 * would be worse than refusing it.
 *
 * The returned session carries `identity` shaped for roleAuthz/toolAuthz:
 * `{ email, sub, groups }`.
 */

import type http from 'node:http';
import { log } from '../utils.js';
import {
  OAuthFlowError,
  getServerUrl,
  isOAuthConfigured,
  verifyGoogleAccessToken,
} from './googleOAuthProvider.js';
import { type Identity, getIdentityHeaderName, verifyIdentityJwt } from './identityJwtVerifier.js';

export interface IdentitySession {
  identity: Identity;
  [key: string]: unknown;
}

/**
 * Build the 401 a client needs in order to discover our authorization
 * server. Per RFC 9728 the WWW-Authenticate header points at the
 * protected-resource metadata document, which names the AS.
 *
 * FastMCP/mcp-proxy writes a thrown Response straight to the wire, headers
 * and all — this is the documented way to fail authentication.
 */
function unauthorized(error: string, description: string, status: number): Response {
  const resourceMetadata = new URL(
    '/.well-known/oauth-protected-resource',
    getServerUrl(),
  ).toString();
  return new Response(JSON.stringify({ error, error_description: description }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'WWW-Authenticate': `Bearer error="${error}", error_description="${description}", resource_metadata="${resourceMetadata}"`,
    },
  });
}

function readBearerToken(request: http.IncomingMessage): string | undefined {
  const raw = request.headers.authorization;
  const header = Array.isArray(raw) ? raw[0] : raw;
  if (!header || !header.startsWith('Bearer ')) return undefined;
  const token = header.slice('Bearer '.length).trim();
  return token.length > 0 ? token : undefined;
}

/**
 * FastMCP authenticate() hook.
 *
 * `request` is undefined for the stdio transport, where there is no HTTP
 * request to authenticate — return undefined and let RBAC decide.
 */
export async function identityAuthenticate(
  request: http.IncomingMessage | undefined,
): Promise<IdentitySession | undefined> {
  if (!request) return undefined;

  // Path 1: gateway JWT wins when present.
  const headerName = getIdentityHeaderName();
  const rawHeader = request.headers[headerName];
  const jwt = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
  if (jwt && typeof jwt === 'string') {
    const identity = await verifyIdentityJwt(jwt);
    if (identity) return { identity };
  }

  // Path 2: Google Bearer access token.
  const token = readBearerToken(request);
  if (!token) return undefined;

  if (!isOAuthConfigured()) {
    // A Bearer token arrived but this deployment has no Google OAuth
    // configured, so we have no way to validate it. Ignore rather than 401 —
    // preserves behavior for gateway-only and stdio deployments.
    return undefined;
  }

  try {
    const verified = await verifyGoogleAccessToken(token);
    log.debug(`[Auth] Authenticated ${verified.email} via Google access token`);
    // Google tokens carry no group claims — group-driven RBAC is a gateway
    // feature. Bearer-authenticated users therefore resolve to no groups,
    // which means requireRole denies them whenever IDENTITY_ROLE_*_GROUPS is
    // configured. Same tradeoff as cellartracker-mcp.
    return { identity: { email: verified.email, sub: verified.sub, groups: [] } };
  } catch (err) {
    if (err instanceof OAuthFlowError) {
      log.warn(`[Auth] Bearer token rejected: ${err.message}`);
      throw unauthorized(err.code, err.message, err.status);
    }
    log.error(`[Auth] Token verification error: ${(err as Error).message}`);
    throw unauthorized('invalid_token', 'Token verification failed', 401);
  }
}
