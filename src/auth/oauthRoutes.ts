/**
 * OAuth authorization-server routes, mounted on FastMCP's underlying Hono app.
 *
 * cellartracker-mcp mounts the equivalent surface with the MCP SDK's Express
 * `mcpAuthRouter`. FastMCP owns its HTTP server, so we register the same
 * endpoints on the Hono app returned by `server.getApp()`:
 *
 *   POST /register    Dynamic client registration (RFC 7591)
 *   GET  /authorize   Authorization endpoint → redirects to Google
 *   GET  /callback    Google's redirect back to us
 *   POST /token       Token endpoint (authorization_code + refresh_token)
 *   POST /revoke      Revocation endpoint (RFC 7009)
 *
 * It also serves the three discovery documents:
 *
 *   GET /.well-known/oauth-authorization-server
 *   GET /.well-known/oauth-protected-resource
 *   GET /.well-known/oauth-protected-resource/mcp
 *
 * Routes registered on the Hono app are only reached for requests FastMCP
 * did not handle itself (i.e. not /mcp), and FastMCP's `authenticate` hook
 * does NOT run for them — which is what we need, since the whole point of
 * these endpoints is to be reachable by an unauthenticated client.
 */

import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { Context, Hono } from 'hono';
import { log } from '../utils.js';
import {
  OAuthFlowError,
  SUPPORTED_SCOPES,
  exchangeAuthorizationCode,
  exchangeRefreshToken,
  getChallengeResourceBase,
  getClient,
  getServerUrl,
  handleGoogleCallback,
  registerClient,
  revokeToken,
  startAuthorization,
} from './googleOAuthProvider.js';

const debug = (message: string): void => log.debug(message);
const info = (message: string): void => log.info(message);
const logError = (message: string): void => log.error(message);

const SERVICE_DOCUMENTATION = 'https://github.com/cswkim/discogs-mcp-server';

/**
 * Emit an RFC 6749 §5.2 error body with the matching HTTP status.
 * Unknown errors become a generic server_error so internal details from
 * thrown exceptions never reach the client.
 */
function errorResponse(c: Context, err: unknown): Response {
  if (err instanceof OAuthFlowError) {
    // Hono types the status as a literal union; our OAuthFlowError statuses
    // are all valid client/server error codes.
    return c.json({ error: err.code, error_description: err.message }, err.status as 400);
  }
  logError(`[OAuth] Unhandled error: ${(err as Error)?.message ?? String(err)}`);
  return c.json({ error: 'server_error', error_description: 'Internal server error' }, 500);
}

/**
 * Read form-encoded or JSON body into a flat string map. MCP clients post
 * `application/x-www-form-urlencoded` per the OAuth specs, but some send
 * JSON; accept both rather than failing opaquely.
 */
async function readBody(c: Context): Promise<Record<string, string>> {
  const contentType = c.req.header('content-type') || '';
  if (contentType.includes('application/json')) {
    const json = (await c.req.json()) as Record<string, unknown>;
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(json)) {
      if (typeof value === 'string') out[key] = value;
    }
    return out;
  }
  const form = await c.req.parseBody();
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(form)) {
    if (typeof value === 'string') out[key] = value;
  }
  return out;
}

/**
 * Authenticate the client at the token/revocation endpoint.
 *
 * Supports the two methods advertised in the discovery document:
 * `client_secret_post` (client_id + client_secret in the body) and `none`
 * (public clients, PKCE-protected).
 */
async function authenticateClient(
  body: Record<string, string>,
): Promise<OAuthClientInformationFull> {
  const clientId = body.client_id;
  if (!clientId) {
    throw new OAuthFlowError('invalid_client', 401, 'client_id is required');
  }

  const client = await getClient(clientId);
  if (!client) {
    throw new OAuthFlowError('invalid_client', 401, 'Unknown client');
  }

  // Confidential clients must present their secret; public clients must not
  // have one on file.
  if (client.client_secret) {
    if (body.client_secret !== client.client_secret) {
      throw new OAuthFlowError('invalid_client', 401, 'Invalid client_secret');
    }
  }

  return client;
}

/**
 * RFC 8414 authorization-server metadata. Mirrors cellartracker-mcp's live
 * discovery document field-for-field, with Discogs' own issuer.
 *
 * `issuer` keeps its trailing slash deliberately — it is the server's
 * identifier and must match cellartracker's shape.
 */
export function buildAuthorizationServerMetadata(): Record<string, unknown> {
  const serverUrl = getServerUrl();
  const abs = (path: string): string => new URL(path, serverUrl).toString();

  return {
    issuer: serverUrl.toString(),
    authorization_endpoint: abs('/authorize'),
    token_endpoint: abs('/token'),
    revocation_endpoint: abs('/revoke'),
    registration_endpoint: abs('/register'),
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    scopes_supported: SUPPORTED_SCOPES,
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    service_documentation: SERVICE_DOCUMENTATION,
  };
}

/**
 * RFC 9728 protected-resource metadata.
 *
 * `resource` keeps its trailing slash to match cellartracker-mcp. Note that
 * this value is NOT what builds the WWW-Authenticate challenge URL — see
 * buildFastmcpOAuthConfig().
 */
export function buildProtectedResourceMetadata(): Record<string, unknown> {
  const serverUrl = getServerUrl();

  return {
    resource: serverUrl.toString(),
    authorization_servers: [serverUrl.toString()],
    scopes_supported: SUPPORTED_SCOPES,
    resource_documentation: SERVICE_DOCUMENTATION,
  };
}

/**
 * Register the OAuth authorization-server endpoints on FastMCP's Hono app.
 */
export function registerOAuthRoutes(app: Hono): void {
  // -------------------------------------------------------------------------
  // Discovery documents
  //
  // Served here rather than from FastMCP's built-in `oauth` option so the
  // published `resource` / `issuer` keep their trailing slash independently
  // of the concat-safe value the challenge header needs. These routes shadow
  // FastMCP's built-in handler, which only runs if the Hono app 404s.
  // -------------------------------------------------------------------------
  app.get('/.well-known/oauth-authorization-server', (c) =>
    c.json(buildAuthorizationServerMetadata()),
  );

  // Both the bare path and the /mcp-suffixed variant (RFC 9728 §3.1) — MCP
  // clients probe the one matching the resource they were denied access to.
  app.get('/.well-known/oauth-protected-resource', (c) => c.json(buildProtectedResourceMetadata()));
  app.get('/.well-known/oauth-protected-resource/mcp', (c) =>
    c.json(buildProtectedResourceMetadata()),
  );

  // -------------------------------------------------------------------------
  // POST /register — dynamic client registration (RFC 7591)
  // -------------------------------------------------------------------------
  app.post('/register', async (c) => {
    try {
      const metadata = (await c.req.json()) as Omit<
        OAuthClientInformationFull,
        'client_id' | 'client_id_issued_at'
      >;

      if (!Array.isArray(metadata.redirect_uris) || metadata.redirect_uris.length === 0) {
        throw new OAuthFlowError(
          'invalid_client_metadata',
          400,
          'redirect_uris is required and must be a non-empty array',
        );
      }

      const client = await registerClient(metadata);
      return c.json(client, 201);
    } catch (err) {
      if (err instanceof SyntaxError) {
        return c.json(
          { error: 'invalid_client_metadata', error_description: 'Body must be valid JSON' },
          400,
        );
      }
      return errorResponse(c, err);
    }
  });

  // -------------------------------------------------------------------------
  // GET /authorize — validate the request, then redirect to Google
  // -------------------------------------------------------------------------
  app.get('/authorize', async (c) => {
    const clientId = c.req.query('client_id');
    const redirectUri = c.req.query('redirect_uri');
    const responseType = c.req.query('response_type');
    const codeChallenge = c.req.query('code_challenge');
    const codeChallengeMethod = c.req.query('code_challenge_method');
    const state = c.req.query('state');
    const scope = c.req.query('scope');

    try {
      if (!clientId) {
        throw new OAuthFlowError('invalid_request', 400, 'client_id is required');
      }

      const client = await getClient(clientId);
      if (!client) {
        throw new OAuthFlowError('invalid_client', 400, 'Unknown client');
      }

      // Resolve and validate the redirect URI BEFORE any error can be
      // redirected back — an unvalidated redirect_uri must never be used as
      // a redirect target.
      const resolvedRedirectUri = redirectUri ?? client.redirect_uris[0];
      if (!resolvedRedirectUri || !client.redirect_uris.includes(resolvedRedirectUri)) {
        throw new OAuthFlowError(
          'invalid_request',
          400,
          'redirect_uri is not registered for this client',
        );
      }

      if (responseType !== 'code') {
        throw new OAuthFlowError(
          'unsupported_response_type',
          400,
          'Only response_type=code is supported',
        );
      }
      if (!codeChallenge) {
        throw new OAuthFlowError('invalid_request', 400, 'code_challenge is required (PKCE)');
      }
      if (codeChallengeMethod && codeChallengeMethod !== 'S256') {
        throw new OAuthFlowError(
          'invalid_request',
          400,
          'Only code_challenge_method=S256 is supported',
        );
      }

      const googleUrl = await startAuthorization(client, {
        redirectUri: resolvedRedirectUri,
        codeChallenge,
        state,
        scopes: scope ? scope.split(' ') : undefined,
      });

      return c.redirect(googleUrl, 302);
    } catch (err) {
      return errorResponse(c, err);
    }
  });

  // -------------------------------------------------------------------------
  // GET /callback — Google redirects the user back here
  // -------------------------------------------------------------------------
  app.get('/callback', async (c) => {
    const code = c.req.query('code');
    const state = c.req.query('state');
    const oauthError = c.req.query('error');

    if (oauthError) {
      logError(`[OAuth] OAuth error from Google: ${oauthError}`);
      return c.text('OAuth error', 400);
    }
    if (!code || !state) {
      return c.text('Missing code or state parameter', 400);
    }

    try {
      const { redirectUrl } = await handleGoogleCallback(code, state);
      info('[OAuth] OAuth callback successful, redirecting to MCP client');
      return c.redirect(redirectUrl, 302);
    } catch (err) {
      logError(`[OAuth] Error handling OAuth callback: ${(err as Error).message}`);
      // Invalid/expired state → 400, not 500. Never echo the error message to
      // the user since it could leak details about server-side state.
      return c.text('Invalid OAuth callback', 400);
    }
  });

  // -------------------------------------------------------------------------
  // POST /token — authorization_code and refresh_token grants
  // -------------------------------------------------------------------------
  app.post('/token', async (c) => {
    try {
      const body = await readBody(c);
      const grantType = body.grant_type;

      if (grantType === 'authorization_code') {
        const client = await authenticateClient(body);
        if (!body.code) {
          throw new OAuthFlowError('invalid_request', 400, 'code is required');
        }
        const tokens = await exchangeAuthorizationCode(
          client,
          body.code,
          body.code_verifier,
          body.redirect_uri,
        );
        debug(`[OAuth] Issued tokens to client ${client.client_id}`);
        return c.json(tokens, 200);
      }

      if (grantType === 'refresh_token') {
        await authenticateClient(body);
        if (!body.refresh_token) {
          throw new OAuthFlowError('invalid_request', 400, 'refresh_token is required');
        }
        const tokens = await exchangeRefreshToken(body.refresh_token);
        return c.json(tokens, 200);
      }

      throw new OAuthFlowError(
        'unsupported_grant_type',
        400,
        `Unsupported grant_type: ${grantType ?? '<none>'}`,
      );
    } catch (err) {
      return errorResponse(c, err);
    }
  });

  // -------------------------------------------------------------------------
  // POST /revoke — revocation (RFC 7009)
  // -------------------------------------------------------------------------
  app.post('/revoke', async (c) => {
    try {
      const body = await readBody(c);
      await authenticateClient(body);
      if (!body.token) {
        throw new OAuthFlowError('invalid_request', 400, 'token is required');
      }
      await revokeToken(body.token);
      // RFC 7009 §2.2: the endpoint answers 200 even for unknown tokens.
      return c.body(null, 200);
    } catch (err) {
      return errorResponse(c, err);
    }
  });

  info(
    '[OAuth] Mounted OAuth routes: /register, /authorize, /callback, /token, /revoke, /.well-known/*',
  );
}

/**
 * Build the FastMCP `oauth` option.
 *
 * Its ONLY job is to feed mcp-proxy the base for the WWW-Authenticate
 * challenge on 401s from /mcp — that header is how MCP clients discover this
 * authorization server. The discovery documents themselves are served by the
 * Hono routes in registerOAuthRoutes(), which shadow FastMCP's built-in
 * handler.
 *
 * `authorizationServer` is intentionally omitted: without it FastMCP will not
 * serve an authorization-server document at all, leaving exactly one
 * definition of each published document (in this module).
 */
export function buildFastmcpOAuthConfig() {
  return {
    enabled: true,
    protectedResource: {
      resource: getChallengeResourceBase(),
      authorizationServers: [getServerUrl().toString()],
    },
  };
}
