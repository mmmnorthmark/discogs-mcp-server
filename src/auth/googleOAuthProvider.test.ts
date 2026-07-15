import { createHash } from 'node:crypto';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';

// Force memory backend so the client/code stores never touch sqlite or firestore.
vi.stubEnv('STORAGE_BACKEND', 'memory');

// Reset module state between tests so each test gets a fresh store and a fresh
// read of the env vars (all of which are read at call time).
beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function loadProvider() {
  return await import('./googleOAuthProvider.js');
}

function s256(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

// ---------------------------------------------------------------------------
// isOAuthConfigured
// ---------------------------------------------------------------------------

describe('isOAuthConfigured', () => {
  it('is false when the Google credentials are absent', async () => {
    vi.stubEnv('GOOGLE_CLIENT_ID', '');
    vi.stubEnv('GOOGLE_CLIENT_SECRET', '');
    vi.stubEnv('MCP_SERVER_URL', '');
    const { isOAuthConfigured } = await loadProvider();
    expect(isOAuthConfigured()).toBe(false);
  });

  it('is false when only some of the required vars are set', async () => {
    vi.stubEnv('GOOGLE_CLIENT_ID', 'gid');
    vi.stubEnv('GOOGLE_CLIENT_SECRET', '');
    vi.stubEnv('MCP_SERVER_URL', 'https://discogs.example.com/');
    const { isOAuthConfigured } = await loadProvider();
    expect(isOAuthConfigured()).toBe(false);
  });

  it('is true when all three required vars are set', async () => {
    vi.stubEnv('GOOGLE_CLIENT_ID', 'gid');
    vi.stubEnv('GOOGLE_CLIENT_SECRET', 'gsecret');
    vi.stubEnv('MCP_SERVER_URL', 'https://discogs.example.com/');
    const { isOAuthConfigured } = await loadProvider();
    expect(isOAuthConfigured()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

describe('verifyPkceS256', () => {
  it('accepts a verifier whose S256 hash matches the challenge', async () => {
    const { verifyPkceS256 } = await loadProvider();
    expect(verifyPkceS256('the-verifier', s256('the-verifier'))).toBe(true);
  });

  it('rejects a mismatched verifier', async () => {
    const { verifyPkceS256 } = await loadProvider();
    expect(verifyPkceS256('wrong-verifier', s256('the-verifier'))).toBe(false);
  });

  it('rejects a plain (unhashed) verifier presented as the challenge', async () => {
    const { verifyPkceS256 } = await loadProvider();
    expect(verifyPkceS256('the-verifier', 'the-verifier')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Scope normalization
// ---------------------------------------------------------------------------

describe('normalizeGoogleScopes', () => {
  it('maps Google URL scopes to standard names', async () => {
    const { normalizeGoogleScopes } = await loadProvider();
    const scopes = normalizeGoogleScopes(
      'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid',
    );
    expect(scopes.sort()).toEqual(['email', 'openid', 'profile']);
  });

  it('passes through already-normalized scopes and deduplicates', async () => {
    const { normalizeGoogleScopes } = await loadProvider();
    expect(normalizeGoogleScopes('email email profile').sort()).toEqual(['email', 'profile']);
  });

  it('returns an empty array for an undefined scope string', async () => {
    const { normalizeGoogleScopes } = await loadProvider();
    expect(normalizeGoogleScopes(undefined)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Email allowlist
// ---------------------------------------------------------------------------

describe('assertEmailAllowed', () => {
  it('is a no-op when ALLOWED_GOOGLE_EMAILS is unset', async () => {
    vi.stubEnv('ALLOWED_GOOGLE_EMAILS', '');
    const { assertEmailAllowed } = await loadProvider();
    expect(() => assertEmailAllowed('anyone@example.com')).not.toThrow();
  });

  it('allows an email on the list, case-insensitively', async () => {
    vi.stubEnv('ALLOWED_GOOGLE_EMAILS', 'matthew@example.com, other@example.com');
    const { assertEmailAllowed } = await loadProvider();
    expect(() => assertEmailAllowed('Matthew@Example.com')).not.toThrow();
  });

  it('denies an email that is not on the list', async () => {
    vi.stubEnv('ALLOWED_GOOGLE_EMAILS', 'matthew@example.com');
    const { OAuthFlowError, assertEmailAllowed } = await loadProvider();
    try {
      assertEmailAllowed('intruder@example.com');
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(OAuthFlowError);
      expect((err as InstanceType<typeof OAuthFlowError>).status).toBe(403);
      expect((err as InstanceType<typeof OAuthFlowError>).code).toBe('insufficient_scope');
    }
  });

  it('denies when no email is present at all', async () => {
    vi.stubEnv('ALLOWED_GOOGLE_EMAILS', 'matthew@example.com');
    const { OAuthFlowError, assertEmailAllowed } = await loadProvider();
    expect(() => assertEmailAllowed(undefined)).toThrow(OAuthFlowError);
  });

  it('bypasses the allowlist for a request carrying a verified gateway identity', async () => {
    vi.stubEnv('ALLOWED_GOOGLE_EMAILS', 'matthew@example.com');
    const { assertEmailAllowed } = await loadProvider();
    const { identityContext } = await import('./identityJwtVerifier.js');

    // The gateway has already applied its own policy, so an email that is NOT
    // on the env allowlist must still be admitted.
    identityContext.run({ email: 'gateway-user@example.com', sub: 'g-1', groups: [] }, () => {
      expect(() => assertEmailAllowed('gateway-user@example.com')).not.toThrow();
    });
  });
});

// ---------------------------------------------------------------------------
// Dynamic client registration
// ---------------------------------------------------------------------------

describe('registerClient / getClient', () => {
  it('mints an mcp-prefixed client id and persists it', async () => {
    const { getClient, registerClient } = await loadProvider();

    const client = await registerClient({
      client_name: 'Test Client',
      redirect_uris: ['https://client.example.com/callback'],
      token_endpoint_auth_method: 'none',
    });

    expect(client.client_id).toMatch(/^mcp-/);
    expect(client.client_id_issued_at).toBeTypeOf('number');

    const fetched = await getClient(client.client_id);
    expect(fetched?.client_name).toBe('Test Client');
  });

  it('issues a secret for confidential clients but not for public ones', async () => {
    const { registerClient } = await loadProvider();

    const publicClient = await registerClient({
      redirect_uris: ['https://client.example.com/callback'],
      token_endpoint_auth_method: 'none',
    });
    expect(publicClient.client_secret).toBeUndefined();

    const confidentialClient = await registerClient({
      redirect_uris: ['https://client.example.com/callback'],
      token_endpoint_auth_method: 'client_secret_post',
    });
    expect(confidentialClient.client_secret).toBeTypeOf('string');
    // Never expires, matching cellartracker-mcp.
    expect(confidentialClient.client_secret_expires_at).toBe(0);
  });

  it('returns undefined for an unknown, non-URL client id', async () => {
    const { getClient } = await loadProvider();
    expect(await getClient('mcp-does-not-exist')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// CIMD (URL-based client_id)
// ---------------------------------------------------------------------------

describe('getClient with a URL client_id (CIMD)', () => {
  const cimdUrl = 'https://client.example.com/mcp-client.json';

  it('fetches and caches the client metadata document', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          client_id: cimdUrl,
          client_name: 'CIMD Client',
          redirect_uris: ['https://client.example.com/callback'],
        }),
        { status: 200 },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const { getClient } = await loadProvider();

    const first = await getClient(cimdUrl);
    expect(first?.client_name).toBe('CIMD Client');
    expect(first?.token_endpoint_auth_method).toBe('none');

    // Second lookup must be served from the in-memory cache.
    const second = await getClient(cimdUrl);
    expect(second?.client_name).toBe('CIMD Client');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('rejects a document whose client_id does not match the URL it came from', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            client_id: 'https://attacker.example.com/other.json',
            redirect_uris: ['https://attacker.example.com/callback'],
          }),
          { status: 200 },
        ),
      ),
    );

    const { getClient } = await loadProvider();
    expect(await getClient(cimdUrl)).toBeUndefined();
  });

  it('rejects a document with no redirect_uris', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ client_id: cimdUrl, redirect_uris: [] }), { status: 200 }),
        ),
    );

    const { getClient } = await loadProvider();
    expect(await getClient(cimdUrl)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Token verification (Google tokeninfo passthrough)
// ---------------------------------------------------------------------------

describe('verifyGoogleAccessToken', () => {
  beforeEach(() => {
    vi.stubEnv('GOOGLE_CLIENT_ID', 'google-client-id');
    vi.stubEnv('ALLOWED_GOOGLE_EMAILS', '');
  });

  it('returns the identity for a valid token', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            aud: 'google-client-id',
            email: 'matthew@example.com',
            email_verified: 'true',
            expires_in: '3600',
            scope: 'openid email',
            sub: 'google-sub-1',
          }),
          { status: 200 },
        ),
      ),
    );

    const { verifyGoogleAccessToken } = await loadProvider();
    const verified = await verifyGoogleAccessToken('good-token');

    expect(verified.email).toBe('matthew@example.com');
    expect(verified.sub).toBe('google-sub-1');
    expect(verified.emailVerified).toBe(true);
    expect(verified.scopes.sort()).toEqual(['email', 'openid']);
  });

  it('rejects a token Google does not recognize', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{}', { status: 400 })));

    const { OAuthFlowError, verifyGoogleAccessToken } = await loadProvider();
    await expect(verifyGoogleAccessToken('bad-token')).rejects.toThrow(OAuthFlowError);
  });

  it('rejects a token minted for a different Google client (aud mismatch)', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          new Response(
            JSON.stringify({ aud: 'someone-elses-client-id', email: 'a@b.com', sub: 's' }),
            { status: 200 },
          ),
        ),
    );

    const { verifyGoogleAccessToken } = await loadProvider();
    await expect(verifyGoogleAccessToken('foreign-token')).rejects.toThrow(
      /not issued for this application/,
    );
  });

  it('applies the email allowlist to an otherwise valid token', async () => {
    vi.stubEnv('ALLOWED_GOOGLE_EMAILS', 'matthew@example.com');
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            aud: 'google-client-id',
            email: 'intruder@example.com',
            sub: 'google-sub-2',
          }),
          { status: 200 },
        ),
      ),
    );

    const { verifyGoogleAccessToken } = await loadProvider();
    await expect(verifyGoogleAccessToken('valid-but-denied')).rejects.toThrow(
      /not authorized for this MCP server/,
    );
  });
});

// ---------------------------------------------------------------------------
// Authorization code flow
// ---------------------------------------------------------------------------

describe('startAuthorization / handleGoogleCallback', () => {
  beforeEach(() => {
    vi.stubEnv('GOOGLE_CLIENT_ID', 'google-client-id');
    vi.stubEnv('GOOGLE_CLIENT_SECRET', 'google-secret');
    vi.stubEnv('MCP_SERVER_URL', 'https://discogs.example.com/');
  });

  const client = {
    client_id: 'mcp-abc',
    redirect_uris: ['https://client.example.com/callback'],
    client_id_issued_at: 0,
  };

  it('redirects to Google with our opaque code as the state', async () => {
    const { startAuthorization } = await loadProvider();

    const url = new URL(
      await startAuthorization(client, {
        redirectUri: 'https://client.example.com/callback',
        codeChallenge: s256('v'),
        state: 'client-state',
      }),
    );

    expect(url.origin + url.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(url.searchParams.get('client_id')).toBe('google-client-id');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('redirect_uri')).toBe('https://discogs.example.com/callback');
    expect(url.searchParams.get('scope')).toBe('openid email profile');
    // The client's own state must NOT be echoed to Google — only our opaque
    // lookup key, so a forged /callback cannot smuggle a redirect target.
    expect(url.searchParams.get('state')).not.toBe('client-state');
    expect(url.searchParams.get('state')).toBeTruthy();
  });

  it('round-trips the callback back to the stored redirect_uri and client state', async () => {
    const { handleGoogleCallback, startAuthorization } = await loadProvider();

    const googleUrl = new URL(
      await startAuthorization(client, {
        redirectUri: 'https://client.example.com/callback',
        codeChallenge: s256('v'),
        state: 'client-state',
      }),
    );
    const ourCode = googleUrl.searchParams.get('state')!;

    const { redirectUrl } = await handleGoogleCallback('google-code-123', ourCode);
    const redirect = new URL(redirectUrl);

    expect(redirect.origin + redirect.pathname).toBe('https://client.example.com/callback');
    expect(redirect.searchParams.get('code')).toBe(ourCode);
    expect(redirect.searchParams.get('state')).toBe('client-state');
  });

  it('rejects a callback whose state is not a known authorization request', async () => {
    const { OAuthFlowError, handleGoogleCallback } = await loadProvider();
    await expect(handleGoogleCallback('google-code', 'forged-state')).rejects.toThrow(
      OAuthFlowError,
    );
  });
});

describe('exchangeAuthorizationCode', () => {
  beforeEach(() => {
    vi.stubEnv('GOOGLE_CLIENT_ID', 'google-client-id');
    vi.stubEnv('GOOGLE_CLIENT_SECRET', 'google-secret');
    vi.stubEnv('MCP_SERVER_URL', 'https://discogs.example.com/');
  });

  const client = {
    client_id: 'mcp-abc',
    redirect_uris: ['https://client.example.com/callback'],
    client_id_issued_at: 0,
  };

  /** Drive /authorize + /callback and return the code the client would hold. */
  async function codeReadyForExchange(
    provider: Awaited<ReturnType<typeof loadProvider>>,
    verifier: string,
  ): Promise<string> {
    const googleUrl = new URL(
      await provider.startAuthorization(client, {
        redirectUri: 'https://client.example.com/callback',
        codeChallenge: s256(verifier),
      }),
    );
    const ourCode = googleUrl.searchParams.get('state')!;
    await provider.handleGoogleCallback('google-code-123', ourCode);
    return ourCode;
  }

  it('passes Google’s access token straight back to the client', async () => {
    const provider = await loadProvider();
    const code = await codeReadyForExchange(provider, 'my-verifier');

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            access_token: 'google-access-token',
            refresh_token: 'google-refresh-token',
            token_type: 'Bearer',
            expires_in: 3599,
            scope: 'openid email',
          }),
          { status: 200 },
        ),
      ),
    );

    const tokens = await provider.exchangeAuthorizationCode(
      client,
      code,
      'my-verifier',
      'https://client.example.com/callback',
    );

    expect(tokens.access_token).toBe('google-access-token');
    expect(tokens.refresh_token).toBe('google-refresh-token');
  });

  it('rejects a wrong PKCE verifier', async () => {
    const provider = await loadProvider();
    const code = await codeReadyForExchange(provider, 'my-verifier');

    await expect(
      provider.exchangeAuthorizationCode(client, code, 'wrong-verifier', undefined),
    ).rejects.toThrow(/PKCE verification failed/);
  });

  it('requires a code_verifier', async () => {
    const provider = await loadProvider();
    const code = await codeReadyForExchange(provider, 'my-verifier');

    await expect(
      provider.exchangeAuthorizationCode(client, code, undefined, undefined),
    ).rejects.toThrow(/code_verifier is required/);
  });

  it('rejects a redirect_uri that does not match the authorization request', async () => {
    const provider = await loadProvider();
    const code = await codeReadyForExchange(provider, 'my-verifier');

    await expect(
      provider.exchangeAuthorizationCode(
        client,
        code,
        'my-verifier',
        'https://attacker.example.com/callback',
      ),
    ).rejects.toThrow(/redirect_uri does not match/);
  });

  it('rejects a code issued to a different client', async () => {
    const provider = await loadProvider();
    const code = await codeReadyForExchange(provider, 'my-verifier');

    await expect(
      provider.exchangeAuthorizationCode(
        { client_id: 'mcp-someone-else', redirect_uris: [], client_id_issued_at: 0 },
        code,
        'my-verifier',
        undefined,
      ),
    ).rejects.toThrow(/issued to another client/);
  });

  it('rejects an unknown code', async () => {
    const provider = await loadProvider();
    await expect(
      provider.exchangeAuthorizationCode(client, 'never-issued', 'v', undefined),
    ).rejects.toThrow(/not found or expired/);
  });

  it('consumes the code so it cannot be replayed', async () => {
    const provider = await loadProvider();
    const code = await codeReadyForExchange(provider, 'my-verifier');

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ access_token: 'a', token_type: 'Bearer' }), {
          status: 200,
        }),
      ),
    );

    await provider.exchangeAuthorizationCode(client, code, 'my-verifier', undefined);
    await expect(
      provider.exchangeAuthorizationCode(client, code, 'my-verifier', undefined),
    ).rejects.toThrow(/not found or expired/);
  });

  it('maps a Google 4xx to invalid_grant and a 5xx to server_error', async () => {
    const provider = await loadProvider();

    const badCode = await codeReadyForExchange(provider, 'v1');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('nope', { status: 400 })));
    await expect(
      provider.exchangeAuthorizationCode(client, badCode, 'v1', undefined),
    ).rejects.toMatchObject({ code: 'invalid_grant', status: 400 });

    const downCode = await codeReadyForExchange(provider, 'v2');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('boom', { status: 503 })));
    await expect(
      provider.exchangeAuthorizationCode(client, downCode, 'v2', undefined),
    ).rejects.toMatchObject({ code: 'server_error', status: 500 });
  });
});
