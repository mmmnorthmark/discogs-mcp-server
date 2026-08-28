/**
 * IDENTITY_PROXY preset behavior: header selection, per-preset
 * verification (self-minted keys, stubbed fetch), the ALB quirks
 * (padding, kid->PEM, signer check), and the oauth2-proxy trust gate.
 */
import { exportSPKI, generateKeyPair, SignJWT, exportJWK } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const es256 = await generateKeyPair('ES256', { extractable: true });
const es256Jwk = await exportJWK(es256.publicKey);
es256Jwk.kid = 'iap-key-1';
es256Jwk.alg = 'ES256';
const es256Pem = await exportSPKI(es256.publicKey);

const ALB_KID = 'a1b2c3d4-1111-2222-3333-444455556666';
const ALB_ARN = 'arn:aws:elasticloadbalancing:eu-north-1:123456789012:loadbalancer/app/music/abc';

type FetchInput = Parameters<typeof fetch>[0];

function stubFetch(routes: Record<string, string>): ReturnType<typeof vi.fn> {
  const mock = vi.fn(async (url: FetchInput) => {
    const key = Object.keys(routes).find((needle) => url.toString().includes(needle));
    if (!key) throw new Error(`Unexpected fetch: ${url}`);
    return new Response(routes[key], { status: 200 });
  });
  globalThis.fetch = mock as unknown as typeof fetch;
  return mock;
}

async function loadVerifier() {
  const module_ = await import('./identityJwtVerifier.js');
  module_._resetJwksCacheForTests();
  return module_;
}

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('header selection per preset', () => {
  const cases: Array<[string, string]> = [
    ['cloudflare', 'cf-access-jwt-assertion'],
    ['gcp-iap', 'x-goog-iap-jwt-assertion'],
    ['aws-alb', 'x-amzn-oidc-data'],
    ['oauth2-proxy', 'x-forwarded-email'],
  ];
  it.each(cases)('%s -> %s', async (preset, header) => {
    vi.stubEnv('IDENTITY_PROXY', preset);
    const { getIdentityHeaderName } = await loadVerifier();
    expect(getIdentityHeaderName()).toBe(header);
  });

  it('defaults to the Cloudflare header when unset, IDENTITY_HEADER always wins', async () => {
    const { getIdentityHeaderName } = await loadVerifier();
    expect(getIdentityHeaderName()).toBe('cf-access-jwt-assertion');

    vi.stubEnv('IDENTITY_PROXY', 'gcp-iap');
    vi.stubEnv('IDENTITY_HEADER', 'X-My-Custom-Header');
    expect(getIdentityHeaderName()).toBe('x-my-custom-header');
  });
});

describe('gcp-iap preset', () => {
  it('verifies an ES256 token with the IAP issuer and configured audience', async () => {
    vi.stubEnv('IDENTITY_PROXY', 'gcp-iap');
    vi.stubEnv('IDENTITY_AUDIENCE', '/projects/1234/locations/us-central1/services/music');
    const fetchMock = stubFetch({
      'https://www.gstatic.com/iap/verify/public_key-jwk': JSON.stringify({ keys: [es256Jwk] }),
    });
    const { verifyIdentityJwt } = await loadVerifier();

    const jwt = await new SignJWT({ email: 'matthew@example.com' })
      .setProtectedHeader({ alg: 'ES256', kid: 'iap-key-1' })
      .setIssuedAt()
      .setIssuer('https://cloud.google.com/iap')
      .setAudience('/projects/1234/locations/us-central1/services/music')
      .setSubject('accounts.google.com:1234567890')
      .setExpirationTime('5m')
      .sign(es256.privateKey);

    const identity = await verifyIdentityJwt(jwt);
    expect(identity).toEqual({
      email: 'matthew@example.com',
      sub: 'accounts.google.com:1234567890',
      groups: [],
    });
    // and it consulted the gstatic JWK endpoint, not the CF certs URL
    expect(fetchMock.mock.calls[0][0].toString()).toContain('gstatic.com/iap');
  });

  it('is disabled without IDENTITY_AUDIENCE and rejects a wrong audience', async () => {
    vi.stubEnv('IDENTITY_PROXY', 'gcp-iap');
    const { verifyIdentityJwt } = await loadVerifier();
    expect(await verifyIdentityJwt('any.jwt.here')).toBeNull();

    vi.stubEnv('IDENTITY_AUDIENCE', '/projects/1234/global/backendServices/5678');
    stubFetch({ 'public_key-jwk': JSON.stringify({ keys: [es256Jwk] }) });
    const jwt = await new SignJWT({ email: 'matthew@example.com' })
      .setProtectedHeader({ alg: 'ES256', kid: 'iap-key-1' })
      .setIssuedAt()
      .setIssuer('https://cloud.google.com/iap')
      .setAudience('/projects/9999/global/backendServices/1')
      .setSubject('sub-1')
      .setExpirationTime('5m')
      .sign(es256.privateKey);
    expect(await verifyIdentityJwt(jwt)).toBeNull();
  });
});

describe('aws-alb preset', () => {
  function albEnv() {
    vi.stubEnv('IDENTITY_PROXY', 'aws-alb');
    vi.stubEnv('IDENTITY_AWS_REGION', 'eu-north-1');
    vi.stubEnv('IDENTITY_AWS_ALB_ARN', ALB_ARN);
  }

  async function mintAlbToken(overrides: { signer?: string; pad?: boolean } = {}) {
    const jwt = await new SignJWT({ email: 'matthew@example.com', groups: ['Music Writers'] })
      .setProtectedHeader({
        alg: 'ES256',
        kid: ALB_KID,
        signer: overrides.signer ?? ALB_ARN,
      } as never)
      .setIssuedAt()
      .setSubject('alb-sub-1')
      .setExpirationTime('5m')
      .sign(es256.privateKey);
    if (!overrides.pad) return jwt;
    // Reproduce ALB's documented quirk: base64url segments WITH padding.
    return jwt
      .split('.')
      .map((segment) => segment + '='.repeat((4 - (segment.length % 4)) % 4))
      .join('.');
  }

  it('verifies a padded token via the per-kid regional key endpoint', async () => {
    albEnv();
    const fetchMock = stubFetch({
      [`public-keys.auth.elb.eu-north-1.amazonaws.com/${ALB_KID}`]: es256Pem,
    });
    const { identityFromHeaders } = await loadVerifier();

    const token = await mintAlbToken({ pad: true });
    expect(token).toContain('='); // the quirk is actually present
    const identity = await identityFromHeaders({ 'x-amzn-oidc-data': token });
    expect(identity).toEqual({
      email: 'matthew@example.com',
      sub: 'alb-sub-1',
      groups: ['Music Writers'],
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('rejects a token whose signer is not the configured ALB ARN', async () => {
    albEnv();
    stubFetch({ [ALB_KID]: es256Pem });
    const { identityFromHeaders } = await loadVerifier();
    const token = await mintAlbToken({
      signer: 'arn:aws:elasticloadbalancing:eu-north-1:999:loadbalancer/app/evil/x',
    });
    expect(await identityFromHeaders({ 'x-amzn-oidc-data': token })).toBeNull();
  });

  it('returns null without a region and on garbage tokens', async () => {
    vi.stubEnv('IDENTITY_PROXY', 'aws-alb');
    const { identityFromHeaders } = await loadVerifier();
    expect(await identityFromHeaders({ 'x-amzn-oidc-data': 'not-a-token' })).toBeNull();
    vi.stubEnv('IDENTITY_AWS_REGION', 'eu-north-1');
    expect(await identityFromHeaders({ 'x-amzn-oidc-data': 'still.not.valid' })).toBeNull();
  });
});

describe('oauth2-proxy preset', () => {
  it('is rejected without the explicit trust flag', async () => {
    vi.stubEnv('IDENTITY_PROXY', 'oauth2-proxy');
    const { identityFromHeaders } = await loadVerifier();
    expect(
      await identityFromHeaders({
        'x-forwarded-email': 'matthew@example.com',
        'x-forwarded-groups': 'Music Admins',
      }),
    ).toBeNull();
  });

  it('honors plain headers when TRUST_UNSIGNED_PROXY_HEADERS=true', async () => {
    vi.stubEnv('IDENTITY_PROXY', 'oauth2-proxy');
    vi.stubEnv('TRUST_UNSIGNED_PROXY_HEADERS', 'true');
    const { identityFromHeaders } = await loadVerifier();
    const identity = await identityFromHeaders({
      'x-forwarded-email': 'matthew@example.com',
      'x-forwarded-groups': 'Music Admins, Music Readers',
      'x-forwarded-user': 'matthew',
    });
    expect(identity).toEqual({
      email: 'matthew@example.com',
      sub: 'matthew',
      groups: ['Music Admins', 'Music Readers'],
    });
  });

  it('never treats the email header as a JWT via verifyIdentityJwt', async () => {
    vi.stubEnv('IDENTITY_PROXY', 'oauth2-proxy');
    vi.stubEnv('TRUST_UNSIGNED_PROXY_HEADERS', 'true');
    const { verifyIdentityJwt } = await loadVerifier();
    expect(await verifyIdentityJwt('matthew@example.com')).toBeNull();
  });
});
