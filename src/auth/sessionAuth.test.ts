import type http from 'node:http';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Force memory backend so the stores never touch sqlite or firestore.
vi.stubEnv('STORAGE_BACKEND', 'memory');

beforeEach(() => {
  vi.resetModules();
  vi.stubEnv('GOOGLE_CLIENT_ID', 'google-client-id');
  vi.stubEnv('GOOGLE_CLIENT_SECRET', 'google-secret');
  vi.stubEnv('MCP_SERVER_URL', 'https://discogs.example.com/');
  vi.stubEnv('ALLOWED_GOOGLE_EMAILS', '');
  // No identity gateway configured by default → verifyIdentityJwt returns null.
  vi.stubEnv('IDENTITY_JWKS_URL', '');
  vi.stubEnv('CF_ACCESS_TEAM_DOMAIN', '');
  vi.stubEnv('CF_ACCESS_AUD', '');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Minimal stand-in for the Node request FastMCP hands the hook. */
function requestWith(headers: Record<string, string>): http.IncomingMessage {
  return { headers } as unknown as http.IncomingMessage;
}

function tokeninfoResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

async function loadSessionAuth() {
  return await import('./sessionAuth.js');
}

describe('identityAuthenticate — no credentials', () => {
  it('returns undefined for stdio (no request at all)', async () => {
    const { identityAuthenticate } = await loadSessionAuth();
    expect(await identityAuthenticate(undefined)).toBeUndefined();
  });

  it('returns undefined when the request carries no identity at all', async () => {
    const { identityAuthenticate } = await loadSessionAuth();
    expect(await identityAuthenticate(requestWith({}))).toBeUndefined();
  });

  it('returns undefined for a non-Bearer Authorization header', async () => {
    const { identityAuthenticate } = await loadSessionAuth();
    expect(
      await identityAuthenticate(requestWith({ authorization: 'Basic dXNlcjpwYXNz' })),
    ).toBeUndefined();
  });
});

describe('identityAuthenticate — Google bearer token path', () => {
  it('returns an identity shaped for roleAuthz on a valid token', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        tokeninfoResponse({
          aud: 'google-client-id',
          email: 'matthew@example.com',
          email_verified: 'true',
          expires_in: '3600',
          scope: 'openid email',
          sub: 'google-sub-1',
        }),
      ),
    );

    const { identityAuthenticate } = await loadSessionAuth();
    const session = await identityAuthenticate(
      requestWith({ authorization: 'Bearer good-google-token' }),
    );

    expect(session?.identity).toEqual({
      email: 'matthew@example.com',
      sub: 'google-sub-1',
      groups: [],
    });
  });

  it('throws a 401 Response with a resource_metadata hint for an invalid token', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(tokeninfoResponse({}, 400)));

    const { identityAuthenticate } = await loadSessionAuth();

    // A present-but-invalid token must be refused, not downgraded to anonymous.
    const thrown = await identityAuthenticate(
      requestWith({ authorization: 'Bearer bad-token' }),
    ).catch((err: unknown) => err);

    expect(thrown).toBeInstanceOf(Response);
    const res = thrown as Response;
    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://discogs.example.com/.well-known/oauth-protected-resource"',
    );
    expect(await res.json()).toMatchObject({ error: 'invalid_token' });
  });

  it('throws a 403 when the token is valid but the email is not allowlisted', async () => {
    vi.stubEnv('ALLOWED_GOOGLE_EMAILS', 'matthew@example.com');
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        tokeninfoResponse({
          aud: 'google-client-id',
          email: 'intruder@example.com',
          sub: 'google-sub-2',
        }),
      ),
    );

    const { identityAuthenticate } = await loadSessionAuth();
    const thrown = await identityAuthenticate(
      requestWith({ authorization: 'Bearer valid-but-denied' }),
    ).catch((err: unknown) => err);

    expect(thrown).toBeInstanceOf(Response);
    expect((thrown as Response).status).toBe(403);
  });

  it('ignores a bearer token when OAuth is not configured', async () => {
    vi.stubEnv('GOOGLE_CLIENT_ID', '');
    vi.stubEnv('GOOGLE_CLIENT_SECRET', '');
    vi.stubEnv('MCP_SERVER_URL', '');

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const { identityAuthenticate } = await loadSessionAuth();
    // Nothing to validate against, so fall through to anonymous rather than
    // 401 — keeps gateway-only and stdio deployments working.
    expect(await identityAuthenticate(requestWith({ authorization: 'Bearer t' }))).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('identityAuthenticate — gateway JWT wins over bearer token', () => {
  it('uses the gateway identity and never calls Google', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    vi.doMock('./identityJwtVerifier.js', async () => {
      const actual = await vi.importActual<typeof import('./identityJwtVerifier.js')>(
        './identityJwtVerifier.js',
      );
      return {
        ...actual,
        getIdentityHeaderName: () => 'cf-access-jwt-assertion',
        verifyIdentityJwt: vi
          .fn()
          .mockResolvedValue({ email: 'gw@example.com', sub: 'gw-1', groups: ['Discogs Admin'] }),
      };
    });

    const { identityAuthenticate } = await loadSessionAuth();
    const session = await identityAuthenticate(
      requestWith({
        'cf-access-jwt-assertion': 'signed.jwt.here',
        authorization: 'Bearer some-google-token',
      }),
    );

    expect(session?.identity).toEqual({
      email: 'gw@example.com',
      sub: 'gw-1',
      groups: ['Discogs Admin'],
    });
    // Gateway path short-circuits: no tokeninfo call, no allowlist check.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('falls back to the bearer token when the gateway JWT does not verify', async () => {
    vi.doMock('./identityJwtVerifier.js', async () => {
      const actual = await vi.importActual<typeof import('./identityJwtVerifier.js')>(
        './identityJwtVerifier.js',
      );
      return {
        ...actual,
        getIdentityHeaderName: () => 'cf-access-jwt-assertion',
        verifyIdentityJwt: vi.fn().mockResolvedValue(null),
      };
    });

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        tokeninfoResponse({
          aud: 'google-client-id',
          email: 'matthew@example.com',
          sub: 'google-sub-1',
        }),
      ),
    );

    const { identityAuthenticate } = await loadSessionAuth();
    const session = await identityAuthenticate(
      requestWith({
        'cf-access-jwt-assertion': 'garbage',
        authorization: 'Bearer good-google-token',
      }),
    );

    expect(session?.identity.email).toBe('matthew@example.com');
  });
});
