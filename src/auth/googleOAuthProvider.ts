/**
 * Google-token-broker OAuth authorization server — core logic.
 *
 * Ported from cellartracker-mcp's src/auth/googleOAuthProvider.ts. The
 * cellartracker original implements the MCP SDK's `OAuthServerProvider`
 * interface and is mounted through the SDK's Express `mcpAuthRouter`.
 * Discogs runs on FastMCP, which owns its HTTP server, so this module is
 * reimplemented as framework-free functions and mounted as Hono routes by
 * src/auth/oauthRoutes.ts.
 *
 * What this server is: a broker in front of Google. It performs its own
 * dynamic client registration (`mcp-{uuid}` client ids) and mints its own
 * authorization codes (randomUUID), but the `access_token` handed back to
 * the MCP client is *Google's own access token, passed through*. Tokens are
 * therefore validated by calling Google's tokeninfo endpoint — there is no
 * JWT/JWKS validation and no local token signing key.
 *
 * Configuration (env vars, read at call time so a redeploy takes effect
 * without a code change):
 *   MCP_SERVER_URL          Public base URL of this server (issuer).
 *   GOOGLE_CLIENT_ID        Google OAuth client id.
 *   GOOGLE_CLIENT_SECRET    Google OAuth client secret.
 *   ALLOWED_GOOGLE_EMAILS   Comma-separated email allowlist. Empty/unset
 *                           disables the gate.
 */

import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  deleteAuthorizationCode,
  getAuthorizationCode,
  setAuthorizationCode,
} from '../storage/oauth-code-store.js';
import { getOAuthClient, setOAuthClient } from '../storage/oauth-client-store.js';
import { log } from '../utils.js';
import { identityContext } from './identityJwtVerifier.js';

const debug = (message: string): void => log.debug(message);
const info = (message: string): void => log.info(message);
const warn = (message: string): void => log.warn(message);
const logError = (message: string): void => log.error(message);

const DEFAULT_SERVER_URL = 'http://localhost:3001';

/** Scopes this server advertises and requests from Google. */
export const SUPPORTED_SCOPES = ['openid', 'email', 'profile'];

/**
 * An OAuth-shaped failure. `code` is the RFC 6749 / RFC 6750 error code and
 * `status` the HTTP status the route handler should emit. Using one explicit
 * error type keeps the Hono handlers flat — they translate this to a JSON
 * error body without re-deriving status codes.
 */
export class OAuthFlowError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'OAuthFlowError';
  }
}

export interface GoogleTokens {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

/** Result of a successful tokeninfo validation + allowlist check. */
export interface VerifiedGoogleToken {
  email: string;
  sub: string;
  scopes: string[];
  expiresAt: number;
  clientId: string;
  emailVerified: boolean;
}

/**
 * Check if OAuth is configured (all required env vars present).
 */
export function isOAuthConfigured(): boolean {
  return !!(
    process.env.GOOGLE_CLIENT_ID &&
    process.env.GOOGLE_CLIENT_SECRET &&
    process.env.MCP_SERVER_URL
  );
}

/**
 * Public base URL of this server. Trailing slash is normalized on so the
 * issuer matches what cellartracker publishes (`https://host/`).
 */
export function getServerUrl(): URL {
  return new URL(process.env.MCP_SERVER_URL || DEFAULT_SERVER_URL);
}

function getGoogleRedirectUri(): string {
  return new URL('/callback', getServerUrl()).toString();
}

/**
 * Enforce the email allowlist set by ALLOWED_GOOGLE_EMAILS.
 * Reads the env var at call time so a redeploy with a new list takes effect
 * for both new logins and existing tokens on their next request.
 * Empty/unset allowlist disables the gate (back-compat with prior behavior).
 *
 * Bypass: if this request arrived through a trusted identity gateway
 * (Cloudflare Access, Cognito, Auth0, etc.) carrying a verified JWT in the
 * configured identity header, the user has already been gated by that
 * gateway's policy. Skip the env-var allowlist for those requests —
 * ALLOWED_GOOGLE_EMAILS then serves only as an admin trapdoor for direct
 * connections (e.g. MCPJam debugging).
 */
export function assertEmailAllowed(email: string | undefined): void {
  const gatewayIdentity = identityContext.getStore();
  if (gatewayIdentity) {
    if (email && email.toLowerCase() !== gatewayIdentity.email.toLowerCase()) {
      warn(
        `[OAuth] Gateway identity ${gatewayIdentity.email} != Google identity ${email}; trusting gateway identity`,
      );
    }
    return;
  }

  const raw = process.env.ALLOWED_GOOGLE_EMAILS;
  if (!raw) return;

  const allowed = raw
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter((e) => e.length > 0);
  if (allowed.length === 0) return;

  if (!email || !allowed.includes(email.toLowerCase())) {
    warn(`[OAuth] Denied: email ${email ?? '<none>'} not in ALLOWED_GOOGLE_EMAILS allowlist`);
    // Authenticated but not authorized → 403 insufficient_scope.
    throw new OAuthFlowError('insufficient_scope', 403, 'User not authorized for this MCP server');
  }
}

// ---------------------------------------------------------------------------
// Client ID Metadata Documents (CIMD) — URL-based client_id
// ---------------------------------------------------------------------------

const cimdCache = new Map<string, { client: OAuthClientInformationFull; expiresAt: number }>();
const CIMD_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Check if a client_id is a URL (CIMD format).
 */
function isUrlClientId(clientId: string): boolean {
  try {
    const url = new URL(clientId);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
}

/**
 * Fetch and validate a Client ID Metadata Document from its URL.
 * Per MCP spec: https://spec.modelcontextprotocol.io/specification/draft/basic/authorization
 */
async function fetchClientMetadata(clientIdUrl: string): Promise<OAuthClientInformationFull> {
  const cached = cimdCache.get(clientIdUrl);
  if (cached && cached.expiresAt > Date.now()) {
    debug(`[OAuth] Using cached CIMD for ${clientIdUrl}`);
    return cached.client;
  }

  debug(`[OAuth] Fetching CIMD from ${clientIdUrl}`);
  const response = await fetch(clientIdUrl, { headers: { Accept: 'application/json' } });

  if (!response.ok) {
    throw new Error(`Failed to fetch client metadata from ${clientIdUrl}: ${response.status}`);
  }

  const metadata = (await response.json()) as {
    client_id: string;
    client_name?: string;
    client_uri?: string;
    redirect_uris: string[];
    grant_types?: string[];
    response_types?: string[];
    token_endpoint_auth_method?: string;
    scope?: string;
  };

  // The document must self-identify with the URL it was fetched from,
  // otherwise anyone could host a document claiming another client's id.
  if (metadata.client_id !== clientIdUrl) {
    throw new Error(
      `Client ID mismatch: document says ${metadata.client_id}, but was fetched from ${clientIdUrl}`,
    );
  }

  if (!metadata.redirect_uris || metadata.redirect_uris.length === 0) {
    throw new Error('Client metadata must include redirect_uris');
  }

  const client: OAuthClientInformationFull = {
    client_id: metadata.client_id,
    client_name: metadata.client_name,
    client_uri: metadata.client_uri,
    redirect_uris: metadata.redirect_uris,
    grant_types: metadata.grant_types || ['authorization_code', 'refresh_token'],
    response_types: metadata.response_types || ['code'],
    token_endpoint_auth_method: metadata.token_endpoint_auth_method || 'none',
    scope: metadata.scope,
    client_id_issued_at: Math.floor(Date.now() / 1000),
  };

  cimdCache.set(clientIdUrl, { client, expiresAt: Date.now() + CIMD_CACHE_TTL_MS });
  debug(
    `[OAuth] Cached CIMD for ${clientIdUrl}, redirect_uris: ${metadata.redirect_uris.join(', ')}`,
  );
  return client;
}

/**
 * Look up a client: first the persistent registration store, then CIMD if
 * the client_id is a URL. Returns undefined when unknown.
 */
export async function getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
  debug(`[OAuth] getClient called with client_id: ${clientId}`);

  const registered = await getOAuthClient(clientId);
  if (registered) {
    debug(`[OAuth] Found registered client: ${clientId}`);
    return registered;
  }

  if (isUrlClientId(clientId)) {
    debug(`[OAuth] client_id is URL, fetching CIMD from: ${clientId}`);
    try {
      return await fetchClientMetadata(clientId);
    } catch (err) {
      logError(`[OAuth] Failed to fetch CIMD for ${clientId}: ${(err as Error).message}`);
      return undefined;
    }
  }

  debug(`[OAuth] Client not found and not a URL: ${clientId}`);
  return undefined;
}

/**
 * Dynamic client registration (RFC 7591). Mints an `mcp-{uuid}` client id and
 * a secret for confidential clients.
 */
export async function registerClient(
  clientMetadata: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>,
): Promise<OAuthClientInformationFull> {
  const clientId = `mcp-${randomUUID()}`;
  const now = Math.floor(Date.now() / 1000);

  const needsSecret = clientMetadata.token_endpoint_auth_method !== 'none';
  const clientSecret = needsSecret ? randomBytes(32).toString('hex') : undefined;

  const fullClient: OAuthClientInformationFull = {
    ...clientMetadata,
    client_id: clientId,
    client_id_issued_at: now,
    ...(clientSecret && {
      client_secret: clientSecret,
      client_secret_expires_at: 0, // Never expires
    }),
  };

  await setOAuthClient(clientId, fullClient);
  info(`[OAuth] Registered new MCP client: ${clientId}`);
  return fullClient;
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

export interface AuthorizeParams {
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  scopes?: string[];
}

/**
 * Begin the authorization flow: persist a server-minted code carrying the
 * request's trusted parameters, and return the Google authorization URL to
 * redirect the user to.
 *
 * Authorization codes live in persistent storage (oauth-code-store) so
 * /authorize, /callback and /token all see the same entry even when Cloud
 * Run cold-starts a new instance mid-flow.
 *
 * `redirectUri` and `state` are stored here and treated as server-trusted.
 * The /callback handler uses these stored values, NOT the values decoded
 * from the (attacker-influenceable) `state` query parameter — preventing
 * open redirects via crafted state.
 */
export async function startAuthorization(
  client: OAuthClientInformationFull,
  params: AuthorizeParams,
): Promise<string> {
  const googleClientId = process.env.GOOGLE_CLIENT_ID;
  if (!googleClientId) {
    throw new OAuthFlowError('server_error', 500, 'GOOGLE_CLIENT_ID not configured');
  }

  const ourCode = randomUUID();

  await setAuthorizationCode(ourCode, {
    clientId: client.client_id,
    codeChallenge: params.codeChallenge,
    redirectUri: params.redirectUri,
    state: params.state,
    scopes: params.scopes,
  });

  const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  googleAuthUrl.searchParams.set('client_id', googleClientId);
  googleAuthUrl.searchParams.set('response_type', 'code');
  googleAuthUrl.searchParams.set('redirect_uri', getGoogleRedirectUri());
  googleAuthUrl.searchParams.set('scope', SUPPORTED_SCOPES.join(' '));
  googleAuthUrl.searchParams.set('access_type', 'offline');
  googleAuthUrl.searchParams.set('prompt', 'consent');
  // Carry only the opaque `ourCode` lookup key in state. Everything we need
  // at /callback is stored server-side in the auth-code store.
  googleAuthUrl.searchParams.set('state', ourCode);

  debug(`[OAuth] Redirecting to Google OAuth for client ${client.client_id}`);
  return googleAuthUrl.toString();
}

/**
 * Handle the OAuth callback from Google.
 *
 * Security: the `state` query param is opaque from our perspective — Google
 * round-trips whatever we set in startAuthorization, but anyone can also
 * forge a /callback request with any state. We treat state as a *lookup key
 * only* into the auth-code store. The redirect URI and the MCP client's
 * original state are read from that entry (server-trusted), never from the
 * state parameter itself. This prevents an open redirect via a crafted state.
 *
 * Throws if `state` doesn't correspond to a stored authorization request —
 * the /callback route returns HTTP 400 in that case.
 */
export async function handleGoogleCallback(
  code: string,
  state: string,
): Promise<{ redirectUrl: string }> {
  const ourCode = state;
  const codeData = await getAuthorizationCode(ourCode);
  if (!codeData) {
    throw new OAuthFlowError('invalid_request', 400, 'Invalid or expired authorization state');
  }

  // Attach Google's authorization code to the existing entry. We do NOT
  // re-key the entry by Google's code — Google codes contain '/' which
  // Firestore parses as a path separator and rejects. Keeping the entry
  // keyed by our opaque UUID also avoids leaking Google's internal
  // authorization code structure to the MCP client.
  await setAuthorizationCode(ourCode, { ...codeData, googleCode: code });

  // Build the redirect back to the MCP client using the redirect URI stored
  // at /authorize time — already validated against the registered client.
  const redirectUrl = new URL(codeData.redirectUri);
  redirectUrl.searchParams.set('code', ourCode);
  if (codeData.state) {
    redirectUrl.searchParams.set('state', codeData.state);
  }

  return { redirectUrl: redirectUrl.toString() };
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

/**
 * Verify a PKCE S256 challenge. Only S256 is supported — `plain` offers no
 * protection and is not advertised in the discovery document.
 */
export function verifyPkceS256(codeVerifier: string, codeChallenge: string): boolean {
  const computed = createHash('sha256').update(codeVerifier).digest('base64url');
  return computed === codeChallenge;
}

/**
 * Exchange one of our authorization codes for Google's tokens.
 *
 * The caller must have already authenticated the client. This verifies the
 * code binding (client_id, redirect_uri) and the PKCE challenge, then trades
 * the stored Google code for Google's tokens and passes them straight back.
 */
export async function exchangeAuthorizationCode(
  client: OAuthClientInformationFull,
  authorizationCode: string,
  codeVerifier: string | undefined,
  redirectUri: string | undefined,
): Promise<GoogleTokens> {
  const codeData = await getAuthorizationCode(authorizationCode);
  if (!codeData) {
    throw new OAuthFlowError('invalid_grant', 400, 'Authorization code not found or expired');
  }
  if (codeData.clientId !== client.client_id) {
    throw new OAuthFlowError(
      'invalid_grant',
      400,
      'Authorization code was issued to another client',
    );
  }
  if (redirectUri !== undefined && redirectUri !== codeData.redirectUri) {
    throw new OAuthFlowError(
      'invalid_grant',
      400,
      'redirect_uri does not match the authorization request',
    );
  }
  if (!codeVerifier) {
    throw new OAuthFlowError('invalid_request', 400, 'code_verifier is required');
  }
  if (!verifyPkceS256(codeVerifier, codeData.codeChallenge)) {
    throw new OAuthFlowError('invalid_grant', 400, 'PKCE verification failed');
  }
  if (!codeData.googleCode) {
    // Code exists but /callback never recorded Google's code on it. Shouldn't
    // happen in a complete flow; treat as invalid grant.
    throw new OAuthFlowError(
      'invalid_grant',
      400,
      'Authorization code is missing upstream exchange data',
    );
  }

  const googleClientId = process.env.GOOGLE_CLIENT_ID;
  const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!googleClientId || !googleClientSecret) {
    throw new OAuthFlowError('server_error', 500, 'Google OAuth credentials not configured');
  }

  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: googleClientId,
    client_secret: googleClientSecret,
    code: codeData.googleCode,
    redirect_uri: getGoogleRedirectUri(),
  });

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });

  if (!response.ok) {
    const errBody = await response.text();
    logError(`[OAuth] Google token exchange failed: ${errBody}`);
    // Google rejects most often because the code is invalid/expired/already
    // used → invalid_grant (400). 5xx from Google means our server can't
    // complete → server_error (500).
    if (response.status >= 500) {
      throw new OAuthFlowError('server_error', 500, 'Upstream token exchange unavailable');
    }
    throw new OAuthFlowError('invalid_grant', 400, 'Authorization code rejected by Google');
  }

  const tokens = (await response.json()) as GoogleTokens;

  // Single-use: consume the code once Google has accepted it.
  await deleteAuthorizationCode(authorizationCode);

  return {
    access_token: tokens.access_token,
    token_type: tokens.token_type,
    expires_in: tokens.expires_in,
    refresh_token: tokens.refresh_token,
    scope: tokens.scope,
  };
}

/**
 * Exchange a refresh token for new Google tokens.
 */
export async function exchangeRefreshToken(refreshToken: string): Promise<GoogleTokens> {
  const googleClientId = process.env.GOOGLE_CLIENT_ID;
  const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!googleClientId || !googleClientSecret) {
    throw new OAuthFlowError('server_error', 500, 'Google OAuth credentials not configured');
  }

  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: googleClientId,
    client_secret: googleClientSecret,
    refresh_token: refreshToken,
  });

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });

  if (!response.ok) {
    const errBody = await response.text();
    logError(`[OAuth] Google token refresh failed: ${errBody}`);
    if (response.status >= 500) {
      throw new OAuthFlowError('server_error', 500, 'Upstream token refresh unavailable');
    }
    throw new OAuthFlowError('invalid_grant', 400, 'Refresh token invalid or revoked');
  }

  const tokens = (await response.json()) as GoogleTokens;
  return {
    access_token: tokens.access_token,
    token_type: tokens.token_type,
    expires_in: tokens.expires_in,
    scope: tokens.scope,
  };
}

/**
 * Revoke a token upstream at Google. Failures are logged, not thrown — RFC
 * 7009 requires the revocation endpoint to answer 200 regardless.
 */
export async function revokeToken(token: string): Promise<void> {
  const params = new URLSearchParams({ token });

  const response = await fetch('https://oauth2.googleapis.com/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });

  if (!response.ok) {
    logError(`[OAuth] Token revocation failed: ${response.status}`);
  }
}

// ---------------------------------------------------------------------------
// Token verification
// ---------------------------------------------------------------------------

/**
 * Map Google's scope URLs to standard OAuth scope names.
 */
export function normalizeGoogleScopes(scopeString: string | undefined): string[] {
  if (!scopeString) return [];

  const googleScopes = scopeString.split(' ');
  const normalizedScopes: string[] = [];

  for (const scope of googleScopes) {
    if (scope.includes('userinfo.email') || scope === 'email') {
      normalizedScopes.push('email');
    }
    if (scope.includes('userinfo.profile') || scope === 'profile') {
      normalizedScopes.push('profile');
    }
    if (scope.includes('openid') || scope === 'openid') {
      normalizedScopes.push('openid');
    }
    // Keep any scope that is already in normalized (non-URL) form.
    if (!scope.startsWith('https://')) {
      normalizedScopes.push(scope);
    }
  }

  return [...new Set(normalizedScopes)];
}

/**
 * Verify a Google access token via Google's tokeninfo endpoint, confirm it
 * was minted for our Google client, and enforce the email allowlist.
 *
 * The allowlist runs on every request, so a deployment that tightens the
 * list locks out existing sessions on their next call.
 */
export async function verifyGoogleAccessToken(token: string): Promise<VerifiedGoogleToken> {
  const response = await fetch(
    `https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(token)}`,
  );

  if (!response.ok) {
    throw new OAuthFlowError('invalid_token', 401, 'Invalid or expired access token');
  }

  const tokenInfo = (await response.json()) as {
    aud: string;
    email?: string;
    email_verified?: string;
    expires_in?: string;
    scope?: string;
    sub?: string;
  };

  const expectedClientId = process.env.GOOGLE_CLIENT_ID;
  if (tokenInfo.aud !== expectedClientId) {
    throw new OAuthFlowError('invalid_token', 401, 'Token was not issued for this application');
  }

  assertEmailAllowed(tokenInfo.email);

  if (!tokenInfo.email || !tokenInfo.sub) {
    throw new OAuthFlowError('invalid_token', 401, 'Token is missing email or subject');
  }

  const expiresIn = tokenInfo.expires_in ? parseInt(tokenInfo.expires_in, 10) : 3600;
  const scopes = normalizeGoogleScopes(tokenInfo.scope);
  debug(`[OAuth] Token verified for ${tokenInfo.email}, scopes: ${scopes.join(', ')}`);

  return {
    email: tokenInfo.email,
    sub: tokenInfo.sub,
    scopes,
    expiresAt: Math.floor(Date.now() / 1000) + expiresIn,
    clientId: tokenInfo.aud,
    emailVerified: tokenInfo.email_verified === 'true',
  };
}

/**
 * Test-only: clear the in-memory CIMD cache between tests.
 */
export function _resetCimdCacheForTests(): void {
  cimdCache.clear();
}
