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
 *   IDENTITY_HEADER         Header name carrying the JWT (default:
 *                           "cf-access-jwt-assertion").
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
 */

import { createRemoteJWKSet, jwtVerify } from "jose";
import { AsyncLocalStorage } from "node:async_hooks";
import { log } from "../utils.js";

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

interface ResolvedConfig {
  jwksUrl: string;
  issuer: string;
  audience: string;
  emailClaim: string;
  groupsClaim: string;
}

/**
 * Resolve verifier config from env vars. Returns null when the feature
 * should be disabled (no IDENTITY_JWKS_URL and no CF_ACCESS_TEAM_DOMAIN).
 *
 * IDENTITY_* vars take precedence; CF_ACCESS_* vars are derivation fallbacks
 * so existing Cloudflare deployments keep working with no env changes.
 */
function resolveConfig(): ResolvedConfig | null {
  const explicitJwksUrl = process.env.IDENTITY_JWKS_URL;
  const explicitIssuer = process.env.IDENTITY_ISSUER;
  const explicitAudience = process.env.IDENTITY_AUDIENCE;

  const cfTeam = process.env.CF_ACCESS_TEAM_DOMAIN;
  const cfAud = process.env.CF_ACCESS_AUD;

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

  return {
    jwksUrl,
    issuer,
    audience,
    emailClaim: process.env.IDENTITY_EMAIL_CLAIM || "email",
    groupsClaim: process.env.IDENTITY_GROUPS_CLAIM || "groups",
  };
}

/**
 * Resolve the configured header name (lowercased) carrying the gateway JWT.
 * Defaults to `cf-access-jwt-assertion` for back-compat with Cloudflare.
 */
export function getIdentityHeaderName(): string {
  return (process.env.IDENTITY_HEADER || "cf-access-jwt-assertion").toLowerCase();
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
  return value.filter((g): g is string => typeof g === "string");
}

/**
 * Verify an identity-gateway JWT. Returns the verified identity or null if
 * anything fails (signature, expiry, audience, issuer, missing config,
 * missing claims). Never throws — callers should treat null as "no trusted
 * gateway context for this request."
 */
export async function verifyIdentityJwt(
  jwt: string
): Promise<Identity | null> {
  const config = resolveConfig();
  if (!config) return null;

  try {
    const { payload } = await jwtVerify(jwt, getJWKS(config.jwksUrl), {
      issuer: config.issuer,
      audience: config.audience,
    });
    const emailRaw = payload[config.emailClaim];
    const email = typeof emailRaw === "string" ? emailRaw : undefined;
    const sub = typeof payload.sub === "string" ? payload.sub : undefined;
    if (!email || !sub) return null;
    const groups = extractGroups(payload[config.groupsClaim]);
    return { email, sub, groups };
  } catch (err) {
    debug(`Identity JWT verification failed: ${(err as Error).message}`);
    return null;
  }
}

/**
 * Test-only: reset the cached JWKS so tests with stubbed env vars start clean.
 * Production code should never call this.
 */
export function _resetJwksCacheForTests(): void {
  cachedJwks = null;
  cachedJwksUrl = null;
}
