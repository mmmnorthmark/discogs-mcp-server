import { Hono } from 'hono';
import { createHash } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Force memory backend so the client/code stores never touch sqlite or firestore.
vi.stubEnv('STORAGE_BACKEND', 'memory');

beforeEach(() => {
  vi.resetModules();
  vi.stubEnv('GOOGLE_CLIENT_ID', 'google-client-id');
  vi.stubEnv('GOOGLE_CLIENT_SECRET', 'google-secret');
  vi.stubEnv('MCP_SERVER_URL', 'https://discogs.example.com/');
  vi.stubEnv('ALLOWED_GOOGLE_EMAILS', '');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function s256(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Build a Hono app with the OAuth routes mounted, exactly as src/index.ts
 * does against FastMCP's getApp().
 */
async function buildApp() {
  const routes = await import('./oauthRoutes.js');
  const app = new Hono();
  routes.registerOAuthRoutes(app);
  return app;
}

/** Register a public (PKCE-only) client and return it. */
async function registerPublicClient(app: Hono) {
  const res = await app.request('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Test Client',
      redirect_uris: ['https://client.example.com/callback'],
      token_endpoint_auth_method: 'none',
    }),
  });
  return (await res.json()) as { client_id: string; client_secret?: string };
}

// ---------------------------------------------------------------------------
// Discovery document
// ---------------------------------------------------------------------------

/**
 * Assert a URL has no accidental empty path segment, i.e. no `//` anywhere
 * after the scheme separator.
 */
function expectNoDoubleSlash(url: string): void {
  expect(url.replace(/^https?:\/\//, '')).not.toContain('//');
}

describe('discovery documents over HTTP', () => {
  it('serves the authorization-server doc, mirroring cellartracker-mcp', async () => {
    const app = await buildApp();
    const res = await app.request('/.well-known/oauth-authorization-server');

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      issuer: 'https://discogs.example.com/',
      authorization_endpoint: 'https://discogs.example.com/authorize',
      token_endpoint: 'https://discogs.example.com/token',
      revocation_endpoint: 'https://discogs.example.com/revoke',
      registration_endpoint: 'https://discogs.example.com/register',
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      scopes_supported: ['openid', 'email', 'profile'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
      service_documentation: 'https://github.com/cswkim/discogs-mcp-server',
    });
  });

  it('serves the protected-resource doc at both the bare and /mcp paths', async () => {
    const app = await buildApp();
    const expected = {
      resource: 'https://discogs.example.com/',
      authorization_servers: ['https://discogs.example.com/'],
      scopes_supported: ['openid', 'email', 'profile'],
      resource_documentation: 'https://github.com/cswkim/discogs-mcp-server',
    };

    const bare = await app.request('/.well-known/oauth-protected-resource');
    expect(bare.status).toBe(200);
    expect(await bare.json()).toEqual(expected);

    const suffixed = await app.request('/.well-known/oauth-protected-resource/mcp');
    expect(suffixed.status).toBe(200);
    expect(await suffixed.json()).toEqual(expected);
  });

  it('keeps the trailing slash on issuer and resource', async () => {
    const { buildAuthorizationServerMetadata, buildProtectedResourceMetadata } =
      await import('./oauthRoutes.js');

    // Matches cellartracker-mcp's live doc; the challenge URL must not be
    // built by concatenating onto these.
    expect(buildAuthorizationServerMetadata().issuer).toBe('https://discogs.example.com/');
    expect(buildProtectedResourceMetadata().resource).toBe('https://discogs.example.com/');
  });
});

// ---------------------------------------------------------------------------
// WWW-Authenticate challenge URL
//
// Regression: MCP_SERVER_URL normalizes to a trailing slash, and mcp-proxy
// builds the challenge by concatenating `${resource}/.well-known/...`, which
// previously emitted `https://host//.well-known/oauth-protected-resource`.
// ---------------------------------------------------------------------------

describe('challenge resource base', () => {
  it('has no trailing slash, so concatenation yields exactly one', async () => {
    const { getChallengeResourceBase } = await import('./googleOAuthProvider.js');

    expect(getChallengeResourceBase()).toBe('https://discogs.example.com');

    // Mirrors mcp-proxy's exact construction (authentication.ts):
    //   `resource_metadata="${resource}/.well-known/oauth-protected-resource"`
    const challengeUrl = `${getChallengeResourceBase()}/.well-known/oauth-protected-resource`;
    expect(challengeUrl).toBe('https://discogs.example.com/.well-known/oauth-protected-resource');
    expectNoDoubleSlash(challengeUrl);
  });

  it('stays concat-safe when MCP_SERVER_URL is given without a trailing slash', async () => {
    vi.stubEnv('MCP_SERVER_URL', 'https://discogs.example.com');
    const { getChallengeResourceBase } = await import('./googleOAuthProvider.js');

    expectNoDoubleSlash(`${getChallengeResourceBase()}/.well-known/oauth-protected-resource`);
  });

  it('feeds the FastMCP oauth config, which is what mcp-proxy concatenates', async () => {
    const { buildFastmcpOAuthConfig } = await import('./oauthRoutes.js');
    const config = buildFastmcpOAuthConfig();

    expect(config.enabled).toBe(true);
    expect(config.protectedResource.resource).toBe('https://discogs.example.com');
    expectNoDoubleSlash(
      `${config.protectedResource.resource}/.well-known/oauth-protected-resource`,
    );

    // The published doc still names the trailing-slash issuer as its AS.
    expect(config.protectedResource.authorizationServers).toEqual(['https://discogs.example.com/']);
  });
});

// ---------------------------------------------------------------------------
// POST /register
// ---------------------------------------------------------------------------

describe('POST /register', () => {
  it('registers a client and returns 201 with an mcp- client_id', async () => {
    const app = await buildApp();
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Cloudflare MCP Portal',
        redirect_uris: ['https://portal.example.com/callback'],
        token_endpoint_auth_method: 'none',
      }),
    });

    expect(res.status).toBe(201);
    const body = (await res.json()) as { client_id: string; client_name: string };
    expect(body.client_id).toMatch(/^mcp-/);
    expect(body.client_name).toBe('Cloudflare MCP Portal');
  });

  it('rejects registration with no redirect_uris', async () => {
    const app = await buildApp();
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_name: 'No Redirects' }),
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_client_metadata' });
  });

  it('rejects a malformed JSON body', async () => {
    const app = await buildApp();
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json',
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_client_metadata' });
  });
});

// ---------------------------------------------------------------------------
// GET /authorize
// ---------------------------------------------------------------------------

describe('GET /authorize', () => {
  it('redirects a valid request to Google', async () => {
    const app = await buildApp();
    const client = await registerPublicClient(app);

    const res = await app.request(
      `/authorize?client_id=${client.client_id}&response_type=code&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&code_challenge=${s256('v')}&code_challenge_method=S256&state=abc`,
    );

    expect(res.status).toBe(302);
    const location = new URL(res.headers.get('location')!);
    expect(location.origin + location.pathname).toBe(
      'https://accounts.google.com/o/oauth2/v2/auth',
    );
  });

  it('rejects an unknown client', async () => {
    const app = await buildApp();
    const res = await app.request(
      `/authorize?client_id=mcp-nope&response_type=code&code_challenge=${s256('v')}`,
    );

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_client' });
  });

  it('rejects a redirect_uri that is not registered for the client', async () => {
    const app = await buildApp();
    const client = await registerPublicClient(app);

    const res = await app.request(
      `/authorize?client_id=${client.client_id}&response_type=code&redirect_uri=${encodeURIComponent('https://attacker.example.com/steal')}&code_challenge=${s256('v')}`,
    );

    // An unvalidated redirect_uri must never become a redirect target.
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
    expect(await res.json()).toMatchObject({ error: 'invalid_request' });
  });

  it('requires PKCE', async () => {
    const app = await buildApp();
    const client = await registerPublicClient(app);

    const res = await app.request(`/authorize?client_id=${client.client_id}&response_type=code`);

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_request' });
  });

  it('rejects code_challenge_method=plain', async () => {
    const app = await buildApp();
    const client = await registerPublicClient(app);

    const res = await app.request(
      `/authorize?client_id=${client.client_id}&response_type=code&code_challenge=v&code_challenge_method=plain`,
    );

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_request' });
  });

  it('rejects an unsupported response_type', async () => {
    const app = await buildApp();
    const client = await registerPublicClient(app);

    const res = await app.request(
      `/authorize?client_id=${client.client_id}&response_type=token&code_challenge=${s256('v')}`,
    );

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'unsupported_response_type' });
  });
});

// ---------------------------------------------------------------------------
// GET /callback
// ---------------------------------------------------------------------------

describe('GET /callback', () => {
  it('redirects back to the client with our own code', async () => {
    const app = await buildApp();
    const client = await registerPublicClient(app);

    const authorizeRes = await app.request(
      `/authorize?client_id=${client.client_id}&response_type=code&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&code_challenge=${s256('v')}&state=client-state`,
    );
    const ourCode = new URL(authorizeRes.headers.get('location')!).searchParams.get('state')!;

    const res = await app.request(`/callback?code=google-code&state=${ourCode}`);

    expect(res.status).toBe(302);
    const redirect = new URL(res.headers.get('location')!);
    expect(redirect.origin + redirect.pathname).toBe('https://client.example.com/callback');
    expect(redirect.searchParams.get('code')).toBe(ourCode);
    expect(redirect.searchParams.get('state')).toBe('client-state');
  });

  it('rejects a forged state rather than redirecting anywhere', async () => {
    const app = await buildApp();
    const res = await app.request('/callback?code=google-code&state=forged');

    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
  });

  it('reports an error returned by Google', async () => {
    const app = await buildApp();
    const res = await app.request('/callback?error=access_denied');
    expect(res.status).toBe(400);
  });

  it('rejects a callback missing code or state', async () => {
    const app = await buildApp();
    expect((await app.request('/callback?code=only-code')).status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// POST /token
// ---------------------------------------------------------------------------

describe('POST /token', () => {
  /** Drive register → authorize → callback and return the client + its code. */
  async function clientWithCode(app: Hono, verifier: string) {
    const client = await registerPublicClient(app);
    const authorizeRes = await app.request(
      `/authorize?client_id=${client.client_id}&response_type=code&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&code_challenge=${s256(verifier)}`,
    );
    const ourCode = new URL(authorizeRes.headers.get('location')!).searchParams.get('state')!;
    await app.request(`/callback?code=google-code&state=${ourCode}`);
    return { client, code: ourCode };
  }

  it('exchanges a code for Google’s tokens, passed through unchanged', async () => {
    const app = await buildApp();
    const { client, code } = await clientWithCode(app, 'my-verifier');

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            access_token: 'google-access-token',
            refresh_token: 'google-refresh-token',
            token_type: 'Bearer',
            expires_in: 3599,
          }),
          { status: 200 },
        ),
      ),
    );

    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: client.client_id,
        code,
        code_verifier: 'my-verifier',
        redirect_uri: 'https://client.example.com/callback',
      }).toString(),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      access_token: 'google-access-token',
      refresh_token: 'google-refresh-token',
    });
  });

  it('rejects a wrong PKCE verifier', async () => {
    const app = await buildApp();
    const { client, code } = await clientWithCode(app, 'my-verifier');

    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: client.client_id,
        code,
        code_verifier: 'wrong-verifier',
      }).toString(),
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_grant' });
  });

  it('rejects an unknown client', async () => {
    const app = await buildApp();
    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'mcp-nope',
        code: 'whatever',
      }).toString(),
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_client' });
  });

  it('requires a confidential client to present its secret', async () => {
    const app = await buildApp();
    const registerRes = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://client.example.com/callback'],
        token_endpoint_auth_method: 'client_secret_post',
      }),
    });
    const client = (await registerRes.json()) as { client_id: string; client_secret: string };
    expect(client.client_secret).toBeTypeOf('string');

    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: client.client_id,
        client_secret: 'wrong-secret',
        code: 'whatever',
      }).toString(),
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_client' });
  });

  it('rejects an unsupported grant_type', async () => {
    const app = await buildApp();
    const client = await registerPublicClient(app);

    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: client.client_id,
      }).toString(),
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'unsupported_grant_type' });
  });

  it('refreshes a token', async () => {
    const app = await buildApp();
    const client = await registerPublicClient(app);

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            access_token: 'refreshed-token',
            token_type: 'Bearer',
            expires_in: 3599,
          }),
          { status: 200 },
        ),
      ),
    );

    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: client.client_id,
        refresh_token: 'google-refresh-token',
      }).toString(),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ access_token: 'refreshed-token' });
  });
});

// ---------------------------------------------------------------------------
// POST /revoke
// ---------------------------------------------------------------------------

describe('POST /revoke', () => {
  it('revokes upstream at Google and answers 200', async () => {
    const app = await buildApp();
    const client = await registerPublicClient(app);

    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const res = await app.request('/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: client.client_id,
        token: 'google-access-token',
      }).toString(),
    });

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledWith(
      'https://oauth2.googleapis.com/revoke',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('still answers 200 when Google rejects the revocation (RFC 7009)', async () => {
    const app = await buildApp();
    const client = await registerPublicClient(app);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 400 })));

    const res = await app.request('/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: client.client_id, token: 'unknown-token' }).toString(),
    });

    expect(res.status).toBe(200);
  });

  it('rejects a revocation from an unknown client', async () => {
    const app = await buildApp();
    const res = await app.request('/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: 'mcp-nope', token: 't' }).toString(),
    });

    expect(res.status).toBe(401);
  });
});
