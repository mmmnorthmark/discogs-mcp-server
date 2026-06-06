/**
 * FastMCP identity-gateway authentication adapter.
 *
 * Bridges the provider-agnostic identityJwtVerifier into FastMCP's
 * `authenticate(request)` hook. When traffic flows through a trusted
 * identity gateway (Cloudflare Access, Cognito, Auth0, etc.) the gateway
 * injects a signed JWT in a configured header; we verify it and attach the
 * resulting Identity to the session so per-tool role enforcement can read
 * it later via `Context.session?.identity`.
 *
 * Direct (non-gateway) connections, requests with a missing/invalid JWT,
 * and deployments that haven't configured an identity provider all return
 * `undefined` here so FastMCP still serves the request without an
 * identity. Whether unauthenticated traffic is rejected is the job of
 * roleAuthz (RBAC) when configured, or of the platform fronting this
 * service (e.g. Cloud Run IAM + a Cloudflare Worker).
 */

import type http from 'node:http';
import { type Identity, getIdentityHeaderName, verifyIdentityJwt } from './identityJwtVerifier.js';

export interface IdentitySession {
  identity: Identity;
  [key: string]: unknown;
}

/**
 * FastMCP authenticate() hook. Reads the configured identity header from
 * the request, verifies its JWT, and returns `{ identity }` on success.
 *
 * Returns `undefined` when no usable identity is present so unauthenticated
 * requests still reach the tool layer — the per-tool requireRole() call is
 * responsible for rejecting them when RBAC is configured.
 */
export async function identityAuthenticate(
  request: http.IncomingMessage,
): Promise<IdentitySession | undefined> {
  const headerName = getIdentityHeaderName();
  const rawHeader = request.headers[headerName];
  const jwt = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
  if (!jwt || typeof jwt !== 'string') return undefined;

  const identity = await verifyIdentityJwt(jwt);
  if (!identity) return undefined;

  return { identity };
}
