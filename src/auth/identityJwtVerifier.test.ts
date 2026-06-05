import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { SignJWT, exportJWK, generateKeyPair } from "jose";

// ---------------------------------------------------------------------------
// Shared crypto setup. Signing is the expensive part — generate one keypair
// for the whole suite and serve its public JWK from the stubbed fetch.
// ---------------------------------------------------------------------------

const { publicKey, privateKey } = await generateKeyPair("RS256");
const publicJwk = await exportJWK(publicKey);
publicJwk.kid = "test-key-1";
publicJwk.alg = "RS256";
publicJwk.use = "sig";

const jwksResponseBody = JSON.stringify({ keys: [publicJwk] });

function stubFetchToServeJwks(expectedUrl: string): void {
  // Use the runtime fetch input type. Discogs's tsconfig omits the DOM lib,
  // so `RequestInfo` isn't a global type here — derive from `typeof fetch`
  // instead so the same test source works under both lib configurations.
  type FetchInput = Parameters<typeof fetch>[0];
  globalThis.fetch = vi.fn(async (url: FetchInput) => {
    if (url.toString() === expectedUrl) {
      return new Response(jwksResponseBody, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    throw new Error(`Unexpected fetch: ${url}`);
  }) as unknown as typeof fetch;
}

interface SignOpts {
  iss: string;
  aud: string | string[];
  sub?: string;
  exp?: number;
  emailClaim?: string;
  email?: string;
  groupsClaim?: string;
  groups?: unknown;
  extraClaims?: Record<string, unknown>;
}

async function signTestJwt(opts: SignOpts): Promise<string> {
  const payload: Record<string, unknown> = { ...(opts.extraClaims ?? {}) };
  if (opts.email !== undefined) {
    payload[opts.emailClaim ?? "email"] = opts.email;
  }
  if (opts.groups !== undefined) {
    payload[opts.groupsClaim ?? "groups"] = opts.groups;
  }

  const builder = new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
    .setIssuedAt()
    .setIssuer(opts.iss)
    .setAudience(opts.aud)
    .setSubject(opts.sub ?? "user-sub-123");
  if (opts.exp !== undefined) {
    builder.setExpirationTime(opts.exp);
  } else {
    builder.setExpirationTime("5m");
  }
  return builder.sign(privateKey);
}

// ---------------------------------------------------------------------------
// Cloudflare back-compat: CF_ACCESS_* alias derivation
// ---------------------------------------------------------------------------

describe("verifyIdentityJwt() — CF_ACCESS_* back-compat derivation", () => {
  const TEAM = "northmark";
  const AUD = "test-app-aud-tag-deadbeef";
  const ISSUER = `https://${TEAM}.cloudflareaccess.com`;
  const JWKS_URL = `https://${TEAM}.cloudflareaccess.com/cdn-cgi/access/certs`;

  beforeEach(() => {
    vi.resetModules();
    vi.stubEnv("CF_ACCESS_TEAM_DOMAIN", TEAM);
    vi.stubEnv("CF_ACCESS_AUD", AUD);
    // Make sure no IDENTITY_* leak through from the host env
    vi.stubEnv("IDENTITY_JWKS_URL", "");
    vi.stubEnv("IDENTITY_ISSUER", "");
    vi.stubEnv("IDENTITY_AUDIENCE", "");
    vi.stubEnv("IDENTITY_HEADER", "");
    vi.stubEnv("IDENTITY_EMAIL_CLAIM", "");
    vi.stubEnv("IDENTITY_GROUPS_CLAIM", "");
    stubFetchToServeJwks(JWKS_URL);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("verifies a JWT signed for the derived Cloudflare issuer/audience", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      email: "wife@example.com",
    });
    const identity = await verifyIdentityJwt(jwt);
    expect(identity).toEqual({
      email: "wife@example.com",
      sub: "user-sub-123",
      groups: [],
    });
  });

  it("returns null when CF_ACCESS_TEAM_DOMAIN is unset and no IDENTITY_JWKS_URL (feature disabled)", async () => {
    vi.stubEnv("CF_ACCESS_TEAM_DOMAIN", "");
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      email: "wife@example.com",
    });
    const identity = await verifyIdentityJwt(jwt);
    expect(identity).toBeNull();
  });

  it("returns null when CF_ACCESS_AUD is unset and no IDENTITY_AUDIENCE (feature disabled)", async () => {
    vi.stubEnv("CF_ACCESS_AUD", "");
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      email: "wife@example.com",
    });
    const identity = await verifyIdentityJwt(jwt);
    expect(identity).toBeNull();
  });

  it("returns null when the audience does not match the derived AUD", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: "some-other-app-aud",
      email: "wife@example.com",
    });
    expect(await verifyIdentityJwt(jwt)).toBeNull();
  });

  it("returns null when the issuer does not match the derived issuer", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: "https://attacker.example.com",
      aud: AUD,
      email: "wife@example.com",
    });
    expect(await verifyIdentityJwt(jwt)).toBeNull();
  });

  it("returns null when the JWT is expired", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const pastSeconds = Math.floor(Date.now() / 1000) - 60;
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      email: "wife@example.com",
      exp: pastSeconds,
    });
    expect(await verifyIdentityJwt(jwt)).toBeNull();
  });

  it("returns null when the email claim is missing", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({ iss: ISSUER, aud: AUD });
    expect(await verifyIdentityJwt(jwt)).toBeNull();
  });

  it("returns null when the JWT is malformed", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    expect(await verifyIdentityJwt("not-a-real-jwt")).toBeNull();
  });

  it("returns null when the signature was made with a different key", async () => {
    const { privateKey: otherKey } = await generateKeyPair("RS256");
    const jwt = await new SignJWT({ email: "wife@example.com" })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setAudience(AUD)
      .setSubject("user-sub-123")
      .setExpirationTime("5m")
      .sign(otherKey);

    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    expect(await verifyIdentityJwt(jwt)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Explicit IDENTITY_* config (provider-agnostic gateway, e.g. Cognito/Auth0)
// ---------------------------------------------------------------------------

describe("verifyIdentityJwt() — explicit IDENTITY_* config", () => {
  const JWKS_URL = "https://idp.example.com/.well-known/jwks.json";
  const ISSUER = "https://idp.example.com/";
  const AUD = "mcp-resource-server";

  beforeEach(() => {
    vi.resetModules();
    vi.stubEnv("IDENTITY_JWKS_URL", JWKS_URL);
    vi.stubEnv("IDENTITY_ISSUER", ISSUER);
    vi.stubEnv("IDENTITY_AUDIENCE", AUD);
    // CF_ACCESS_* must NOT take precedence
    vi.stubEnv("CF_ACCESS_TEAM_DOMAIN", "should-not-be-used");
    vi.stubEnv("CF_ACCESS_AUD", "should-not-be-used");
    stubFetchToServeJwks(JWKS_URL);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("verifies a JWT against the explicit JWKS URL / issuer / audience", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      email: "user@example.com",
    });
    expect(await verifyIdentityJwt(jwt)).toEqual({
      email: "user@example.com",
      sub: "user-sub-123",
      groups: [],
    });
  });

  it("uses IDENTITY_EMAIL_CLAIM override to pick the email out of a non-default claim", async () => {
    vi.stubEnv("IDENTITY_EMAIL_CLAIM", "user_email");
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      emailClaim: "user_email",
      email: "user@example.com",
    });
    expect((await verifyIdentityJwt(jwt))?.email).toBe("user@example.com");
  });

  it("uses IDENTITY_GROUPS_CLAIM override to pick groups out of a non-default claim", async () => {
    vi.stubEnv("IDENTITY_GROUPS_CLAIM", "cognito:groups");
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      email: "user@example.com",
      groupsClaim: "cognito:groups",
      groups: ["Wine Admin", "Wine Read-Write"],
    });
    expect((await verifyIdentityJwt(jwt))?.groups).toEqual([
      "Wine Admin",
      "Wine Read-Write",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Groups claim extraction (default "groups")
// ---------------------------------------------------------------------------

describe("verifyIdentityJwt() — groups claim extraction", () => {
  const JWKS_URL = "https://idp.example.com/jwks.json";
  const ISSUER = "https://idp.example.com/";
  const AUD = "mcp-aud";

  beforeEach(() => {
    vi.resetModules();
    vi.stubEnv("IDENTITY_JWKS_URL", JWKS_URL);
    vi.stubEnv("IDENTITY_ISSUER", ISSUER);
    vi.stubEnv("IDENTITY_AUDIENCE", AUD);
    stubFetchToServeJwks(JWKS_URL);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("extracts groups when the claim is a string array", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      email: "user@example.com",
      groups: ["Wine Admin", "Wine Read-Only"],
    });
    expect((await verifyIdentityJwt(jwt))?.groups).toEqual([
      "Wine Admin",
      "Wine Read-Only",
    ]);
  });

  it("returns [] when groups claim is missing", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      email: "user@example.com",
    });
    expect((await verifyIdentityJwt(jwt))?.groups).toEqual([]);
  });

  it("returns [] when groups claim is not an array", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      email: "user@example.com",
      groups: "not-an-array",
    });
    expect((await verifyIdentityJwt(jwt))?.groups).toEqual([]);
  });

  it("filters out non-string entries in the groups array", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    const jwt = await signTestJwt({
      iss: ISSUER,
      aud: AUD,
      email: "user@example.com",
      groups: ["ok", 42, null, { x: 1 }, "also-ok"],
    });
    expect((await verifyIdentityJwt(jwt))?.groups).toEqual(["ok", "also-ok"]);
  });
});

// ---------------------------------------------------------------------------
// Feature disabled
// ---------------------------------------------------------------------------

describe("verifyIdentityJwt() — feature disabled", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.stubEnv("IDENTITY_JWKS_URL", "");
    vi.stubEnv("IDENTITY_ISSUER", "");
    vi.stubEnv("IDENTITY_AUDIENCE", "");
    vi.stubEnv("CF_ACCESS_TEAM_DOMAIN", "");
    vi.stubEnv("CF_ACCESS_AUD", "");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns null without throwing when no config env vars are set", async () => {
    const { verifyIdentityJwt } = await import("./identityJwtVerifier.js");
    expect(await verifyIdentityJwt("anything")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Header name resolution
// ---------------------------------------------------------------------------

describe("getIdentityHeaderName()", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("defaults to cf-access-jwt-assertion for back-compat", async () => {
    vi.stubEnv("IDENTITY_HEADER", "");
    const { getIdentityHeaderName } = await import("./identityJwtVerifier.js");
    expect(getIdentityHeaderName()).toBe("cf-access-jwt-assertion");
  });

  it("lowercases the configured header name", async () => {
    vi.stubEnv("IDENTITY_HEADER", "X-Auth-JWT");
    const { getIdentityHeaderName } = await import("./identityJwtVerifier.js");
    expect(getIdentityHeaderName()).toBe("x-auth-jwt");
  });
});

// ---------------------------------------------------------------------------
// identityContext (AsyncLocalStorage)
// ---------------------------------------------------------------------------

describe("identityContext", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("isolates per-async-flow identity", async () => {
    const { identityContext } = await import("./identityJwtVerifier.js");

    const results: Array<string | undefined> = [];

    await Promise.all([
      identityContext.run(
        { email: "a@example.com", sub: "a", groups: [] },
        async () => {
          await new Promise((r) => setTimeout(r, 5));
          results.push(identityContext.getStore()?.email);
        }
      ),
      identityContext.run(
        { email: "b@example.com", sub: "b", groups: [] },
        async () => {
          await new Promise((r) => setTimeout(r, 5));
          results.push(identityContext.getStore()?.email);
        }
      ),
    ]);

    expect(results.sort()).toEqual(["a@example.com", "b@example.com"]);
  });

  it("returns undefined outside of a run()", async () => {
    const { identityContext } = await import("./identityJwtVerifier.js");
    expect(identityContext.getStore()).toBeUndefined();
  });
});
