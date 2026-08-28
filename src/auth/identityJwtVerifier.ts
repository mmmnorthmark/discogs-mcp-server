/**
 * Identity-gateway JWT verifier — provider-agnostic identity passthrough.
 *
 * When traffic flows through a trusted identity gateway (Cloudflare Access,
 * AWS Cognito, Auth0, Tailscale, a future MCP gateway, etc.), the gateway
 * injects a signed JWT header with the end-user's identity. Verifying it
 * lets us trust that the gateway has already gated the request against its
 * policy and bypass the env-var-managed ALLOWED_GOOGLE_EMAILS for those
 * users.
 *
 * Direct connections (no gateway JWT) fall through to ALLOWED_GOOGLE_EMAILS,
 * which serves as an admin-only trapdoor for debugging without the gateway.
 *
 * Configuration (env vars, read at call time):
 *   IDENTITY_HEADER         Header name carrying the JWT (default: the
 *                           active preset's header).
 *   IDENTITY_JWKS_URL       Full URL of the gateway's JWKS endpoint.
 *   IDENTITY_ISSUER         Expected `iss` claim value.
 *   IDENTITY_AUDIENCE       Expected `aud` claim value.
 *   IDENTITY_EMAIL_CLAIM    Claim name carrying the user's email (default:
 *                           "email").
 *   IDENTITY_GROUPS_CLAIM   Claim name carrying group memberships as a
 *                           string array (default: "groups").
 *
 * Cloudflare Access back-compat: if the IDENTITY_* vars above are not set
 * but CF_ACCESS_TEAM_DOMAIN + CF_ACCESS_AUD are, the verifier derives the
 * Cloudflare-specific JWKS URL / issuer / audience automatically and keeps
 * the default `cf-access-jwt-assertion` header. Existing Cloudflare
 * deployments continue to work without any env-var changes.
 *
 * Feature is disabled (returns null without errors) when neither
 * IDENTITY_JWKS_URL nor CF_ACCESS_TEAM_DOMAIN is set.
 *
 * NOTE ON THE CLOUDFLARE MCP PORTAL. The portal does NOT forward
 * Cf-Access-Jwt-Assertion to the origin, so none of this fires for portal
 * traffic — those callers authenticate via OAuth Bearer and carry no
 * groups. Per-tool RBAC behind a portal is therefore driven by the email
 * tiers in roleAuthz.ts. This module is for topologies where the gateway
 * does forward a signed assertion.
 *
 * Vendor presets (IDENTITY_PROXY) — each sets the header + verification
 * defaults for a proxy; explicit IDENTITY_* vars always override:
 *   cloudflare    Cf-Access-Jwt-Assertion, RS256 JWKS at
 *                 https://<CF_ACCESS_TEAM_DOMAIN>.cloudflareaccess.com/cdn-cgi/access/certs,
 *                 aud from CF_ACCESS_AUD.
 *   gcp-iap       x-goog-iap-jwt-assertion, ES256 JWK at
 *                 https://www.gstatic.com/iap/verify/public_key-jwk,
 *                 iss https://cloud.google.com/iap, aud from
 *                 IDENTITY_AUDIENCE (/projects/NUM/... form), 30s clock
 *                 tolerance per Google's guidance.
 *   aws-alb       x-amzn-oidc-data, ES256, per-kid PEM key from
 *                 https://public-keys.auth.elb.<IDENTITY_AWS_REGION>.amazonaws.com/<kid>.
 *                 ALB pads its base64url segments (documented) — padding
 *                 is stripped before verification. The JWT header's
 *                 `signer` field is checked against IDENTITY_AWS_ALB_ARN
 *                 when set (AWS docs say you MUST verify it; a warning is
 *                 logged when unset). No aud claim exists; iss is checked
 *                 only when IDENTITY_ISSUER is set.
 *   oauth2-proxy  PLAIN X-Forwarded-Email / X-Forwarded-Groups headers —
 *                 UNSIGNED. Honored only when
 *                 TRUST_UNSIGNED_PROXY_HEADERS=true is also set: anyone
 *                 who can reach the origin directly can forge these, so
 *                 this mode is for private-network topologies where ONLY
 *                 the proxy can reach the server. Never expose such a
 *                 deployment to the public internet.
 *   custom/unset  The generic four-knob behavior above, unchanged.
 */

import { createRemoteJWKSet, importSPKI, jwtVerify } from 'jose';
import { AsyncLocalStorage } from 'node:async_hooks';
import { log } from '../utils.js';

// Discogs ships a single `log` object instead of cellartracker's named-export
// severity helpers. Alias to keep the rest of this module byte-identical to
// the cellartracker-mcp source it was copied from.
const debug = (message: string): void => log.debug(message);

export interface Identity {
  email: string;
  sub: string;
  groups: string[];
}

// Per-request context. The MCP SDK's requireBearerAuth middleware calls
// verifyAccessToken(token) without passing req, so downstream code needs
// AsyncLocalStorage to read the request-scoped gateway identity.
export const identityContext = new AsyncLocalStorage<Identity>();

export type IdentityProxyPreset = 'cloudflare' | 'gcp-iap' | 'aws-alb' | 'oauth2-proxy' | 'custom';

export function getIdentityProxyPreset(): IdentityProxyPreset {
  const raw = process.env.IDENTITY_PROXY?.trim().toLowerCase();
  if (raw === 'cloudflare' || raw === 'gcp-iap' || raw === 'aws-alb' || raw === 'oauth2-proxy') {
    return raw;
  }
  return 'custom';
}

const PRESET_HEADER: Record<IdentityProxyPreset, string> = {
  cloudflare: 'cf-access-jwt-assertion',
  'gcp-iap': 'x-goog-iap-jwt-assertion',
  'aws-alb': 'x-amzn-oidc-data',
  'oauth2-proxy': 'x-forwarded-email',
  custom: 'cf-access-jwt-assertion',
};

interface ResolvedConfig {
  jwksUrl: string;
  issuer: string;
  audience: string;
  emailClaim: string;
  groupsClaim: string;
  /** Seconds of clock skew tolerated (IAP guidance: 30s). */
  clockTolerance: number;
}

/**
 * Resolve verifier config from env vars. Returns null when the feature
 * should be disabled (no IDENTITY_JWKS_URL and no CF_ACCESS_TEAM_DOMAIN).
 *
 * IDENTITY_* vars take precedence; CF_ACCESS_* vars are derivation fallbacks
 * so existing Cloudflare deployments keep working with no env changes.
 */
function resolveConfig(): ResolvedConfig | null {
  const preset = getIdentityProxyPreset();
  const explicitJwksUrl = process.env.IDENTITY_JWKS_URL;
  const explicitIssuer = process.env.IDENTITY_ISSUER;
  const explicitAudience = process.env.IDENTITY_AUDIENCE;

  const cfTeam = process.env.CF_ACCESS_TEAM_DOMAIN;
  const cfAud = process.env.CF_ACCESS_AUD;

  const claims = {
    emailClaim: process.env.IDENTITY_EMAIL_CLAIM || 'email',
    groupsClaim: process.env.IDENTITY_GROUPS_CLAIM || 'groups',
  };

  if (preset === 'gcp-iap') {
    // Verified against Google's signed-headers docs: ES256 JWKs at
    // gstatic, iss https://cloud.google.com/iap, aud is deployment-
    // specific and must be supplied. 30s skew tolerance recommended.
    const audience = explicitAudience;
    if (!audience) return null;
    return {
      jwksUrl: explicitJwksUrl || 'https://www.gstatic.com/iap/verify/public_key-jwk',
      issuer: explicitIssuer || 'https://cloud.google.com/iap',
      audience,
      clockTolerance: 30,
      ...claims,
    };
  }

  if (preset === 'cloudflare') {
    if (!cfTeam) return null;
    const audience = explicitAudience || cfAud;
    if (!audience) return null;
    return {
      jwksUrl: explicitJwksUrl || `https://${cfTeam}.cloudflareaccess.com/cdn-cgi/access/certs`,
      issuer: explicitIssuer || `https://${cfTeam}.cloudflareaccess.com`,
      audience,
      clockTolerance: 0,
      ...claims,
    };
  }

  // custom / unset: the original four-knob behavior with the CF alias.
  let jwksUrl: string | undefined;
  let issuer: string | undefined;
  let audience: string | undefined;

  if (explicitJwksUrl) {
    jwksUrl = explicitJwksUrl;
    issuer = explicitIssuer;
    audience = explicitAudience;
  } else if (cfTeam && cfAud) {
    jwksUrl = `https://${cfTeam}.cloudflareaccess.com/cdn-cgi/access/certs`;
    issuer = explicitIssuer || `https://${cfTeam}.cloudflareaccess.com`;
    audience = explicitAudience || cfAud;
  } else {
    return null;
  }

  if (!issuer || !audience) return null;

  return { jwksUrl, issuer, audience, clockTolerance: 0, ...claims };
}

/**
 * Resolve the configured header name (lowercased) carrying the gateway JWT.
 * Defaults to the active preset's header (`cf-access-jwt-assertion` when
 * no preset is set, for back-compat with Cloudflare).
 */
export function getIdentityHeaderName(): string {
  return (process.env.IDENTITY_HEADER || PRESET_HEADER[getIdentityProxyPreset()]).toLowerCase();
}

let cachedJwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let cachedJwksUrl: string | null = null;

function getJWKS(jwksUrl: string): ReturnType<typeof createRemoteJWKSet> {
  if (cachedJwks && cachedJwksUrl === jwksUrl) return cachedJwks;
  cachedJwks = createRemoteJWKSet(new URL(jwksUrl));
  cachedJwksUrl = jwksUrl;
  return cachedJwks;
}

function extractGroups(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((g): g is string => typeof g === 'string');
}

/**
 * Verify an identity-gateway JWT. Returns the verified identity or null if
 * anything fails (signature, expiry, audience, issuer, missing config,
 * missing claims). Never throws — callers should treat null as "no trusted
 * gateway context for this request."
 */
export async function verifyIdentityJwt(jwt: string): Promise<Identity | null> {
  const preset = getIdentityProxyPreset();
  if (preset === 'aws-alb') return verifyAlbToken(jwt);
  if (preset === 'oauth2-proxy') {
    // oauth2-proxy forwards plain headers, not a JWT — use
    // identityFromHeaders(), which handles the trust gate.
    return null;
  }

  const config = resolveConfig();
  if (!config) return null;

  try {
    const { payload } = await jwtVerify(jwt, getJWKS(config.jwksUrl), {
      issuer: config.issuer,
      audience: config.audience,
      clockTolerance: config.clockTolerance,
    });
    const emailRaw = payload[config.emailClaim];
    const email = typeof emailRaw === 'string' ? emailRaw : undefined;
    const sub = typeof payload.sub === 'string' ? payload.sub : undefined;
    if (!email || !sub) return null;
    const groups = extractGroups(payload[config.groupsClaim]);
    return { email, sub, groups };
  } catch (err) {
    debug(`Identity JWT verification failed: ${(err as Error).message}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// AWS ALB (x-amzn-oidc-data) verification
// ---------------------------------------------------------------------------

// Per-kid public keys, cached. ALB's key endpoint serves a PEM EC public
// key (not a JWKS document), one key per kid taken from the token header.
const albKeyCache = new Map<string, Promise<CryptoKey>>();

function albKeysBase(): string | null {
  // Test/GovCloud escape hatch first; else the documented regional host.
  const override = process.env.IDENTITY_ALB_KEYS_BASE;
  if (override) return override.replace(/\/$/, '');
  const region = process.env.IDENTITY_AWS_REGION;
  if (!region) return null;
  return `https://public-keys.auth.elb.${region}.amazonaws.com`;
}

async function fetchAlbKey(kid: string): Promise<CryptoKey> {
  const base = albKeysBase();
  if (!base) throw new Error('IDENTITY_AWS_REGION (or IDENTITY_ALB_KEYS_BASE) is not set');
  const cached = albKeyCache.get(kid);
  if (cached) return cached;
  const pending = (async () => {
    const response = await fetch(`${base}/${kid}`);
    if (!response.ok) throw new Error(`ALB key fetch ${kid} -> HTTP ${response.status}`);
    const pem = await response.text();
    return (await importSPKI(pem, 'ES256')) as CryptoKey;
  })();
  albKeyCache.set(kid, pending);
  pending.catch(() => albKeyCache.delete(kid));
  return pending;
}

/**
 * Verify an ALB user-claims token. Documented quirks handled here:
 *   - Segments are base64url WITH padding ("includes padding characters
 *     at the end" — AWS docs); standard JWT parsers reject that, so the
 *     padding is stripped first.
 *   - The kid comes from the token header and keys are fetched per kid
 *     as PEM from the regional endpoint.
 *   - AWS requires verifying the header's `signer` (the ALB's ARN);
 *     enforced when IDENTITY_AWS_ALB_ARN is set, loudly warned otherwise.
 *   - There is no aud claim; iss (the IdP URL, present in the token
 *     HEADER as documented) is not enforced unless IDENTITY_ISSUER is
 *     set, in which case the payload/header iss must match.
 */
async function verifyAlbToken(token: string): Promise<Identity | null> {
  try {
    const stripped = token
      .split('.')
      .map((segment) => segment.replace(/=+$/, ''))
      .join('.');
    const parts = stripped.split('.');
    if (parts.length !== 3) return null;

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as {
      kid?: string;
      signer?: string;
      iss?: string;
      alg?: string;
    };
    if (header.alg !== 'ES256') {
      debug(`ALB token rejected: unexpected alg ${header.alg}`);
      return null;
    }
    if (!header.kid || !/^[A-Za-z0-9-]+$/.test(header.kid)) {
      debug('ALB token rejected: missing or malformed kid');
      return null;
    }

    const expectedArn = process.env.IDENTITY_AWS_ALB_ARN;
    if (expectedArn) {
      if (header.signer !== expectedArn) {
        debug(`ALB token rejected: signer ${header.signer} != ${expectedArn}`);
        return null;
      }
    } else {
      log.warn(
        '[Auth] IDENTITY_AWS_ALB_ARN not set - accepting any ALB in the region as signer. ' +
          'AWS docs require verifying the signer field; set the ARN.',
      );
    }

    const key = await fetchAlbKey(header.kid);
    const expectedIssuer = process.env.IDENTITY_ISSUER;
    const { payload } = await jwtVerify(stripped, key, {
      algorithms: ['ES256'],
      ...(expectedIssuer ? { issuer: expectedIssuer } : {}),
    });

    const emailClaim = process.env.IDENTITY_EMAIL_CLAIM || 'email';
    const groupsClaim = process.env.IDENTITY_GROUPS_CLAIM || 'groups';
    const emailRaw = payload[emailClaim];
    const email = typeof emailRaw === 'string' ? emailRaw : undefined;
    const sub = typeof payload.sub === 'string' ? payload.sub : undefined;
    if (!email || !sub) return null;
    return { email, sub, groups: extractGroups(payload[groupsClaim]) };
  } catch (err) {
    debug(`ALB token verification failed: ${(err as Error).message}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Header-level entry point (all presets, incl. non-JWT oauth2-proxy)
// ---------------------------------------------------------------------------

type HeaderBag = Record<string, string | string[] | undefined>;

function headerValue(headers: HeaderBag, name: string): string | undefined {
  const raw = headers[name] ?? headers[name.toLowerCase()];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return value && value.length > 0 ? value : undefined;
}

/**
 * Resolve a proxy-forwarded identity from a request's headers. This is
 * the preferred entry point: it picks the right header for the active
 * IDENTITY_PROXY preset and handles the unsigned oauth2-proxy mode,
 * which has no JWT for verifyIdentityJwt() to verify.
 */
export async function identityFromHeaders(headers: HeaderBag): Promise<Identity | null> {
  const preset = getIdentityProxyPreset();

  if (preset === 'oauth2-proxy') {
    if (process.env.TRUST_UNSIGNED_PROXY_HEADERS !== 'true') {
      debug(
        'IDENTITY_PROXY=oauth2-proxy but TRUST_UNSIGNED_PROXY_HEADERS is not "true" - ' +
          'refusing to honor unsigned X-Forwarded-* headers',
      );
      return null;
    }
    const email = headerValue(headers, 'x-forwarded-email');
    if (!email) return null;
    const groupsRaw = headerValue(headers, 'x-forwarded-groups') ?? '';
    const groups = groupsRaw
      .split(',')
      .map((group) => group.trim())
      .filter((group) => group.length > 0);
    const sub = headerValue(headers, 'x-forwarded-user') || email;
    return { email, sub, groups };
  }

  const jwt = headerValue(headers, getIdentityHeaderName());
  if (!jwt) return null;
  return verifyIdentityJwt(jwt);
}

/**
 * Test-only: reset the cached JWKS so tests with stubbed env vars start clean.
 * Production code should never call this.
 */
export function _resetJwksCacheForTests(): void {
  cachedJwks = null;
  cachedJwksUrl = null;
  albKeyCache.clear();
}
