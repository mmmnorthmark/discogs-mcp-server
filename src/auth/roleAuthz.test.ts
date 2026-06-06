import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { InsufficientScopeError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { Identity } from "./identityJwtVerifier.js";

function identityFor(groups: string[]): Identity {
  return { email: "u@example.com", sub: "u-1", groups };
}

// ---------------------------------------------------------------------------
// getRoleFromGroups: returns the HIGHEST tier the user qualifies for
// ---------------------------------------------------------------------------

describe("getRoleFromGroups", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.stubEnv("IDENTITY_ROLE_ADMIN_GROUPS", "Wine Admin");
    vi.stubEnv("IDENTITY_ROLE_WRITER_GROUPS", "Wine Read-Write");
    vi.stubEnv("IDENTITY_ROLE_READER_GROUPS", "Wine Read-Only");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns 'admin' when user is in an admin group", async () => {
    const { getRoleFromGroups } = await import("./roleAuthz.js");
    expect(getRoleFromGroups(["Wine Admin"])).toBe("admin");
  });

  it("returns 'writer' when user is in a writer group only", async () => {
    const { getRoleFromGroups } = await import("./roleAuthz.js");
    expect(getRoleFromGroups(["Wine Read-Write"])).toBe("writer");
  });

  it("returns 'reader' when user is in a reader group only", async () => {
    const { getRoleFromGroups } = await import("./roleAuthz.js");
    expect(getRoleFromGroups(["Wine Read-Only"])).toBe("reader");
  });

  it("returns null when user matches no configured group", async () => {
    const { getRoleFromGroups } = await import("./roleAuthz.js");
    expect(getRoleFromGroups(["Books Admin", "Music Read-Only"])).toBeNull();
  });

  it("returns null when groups is empty", async () => {
    const { getRoleFromGroups } = await import("./roleAuthz.js");
    expect(getRoleFromGroups([])).toBeNull();
  });

  it("returns the HIGHEST role when user belongs to multiple tiers (admin wins over reader)", async () => {
    const { getRoleFromGroups } = await import("./roleAuthz.js");
    expect(
      getRoleFromGroups(["Wine Read-Only", "Wine Admin", "Wine Read-Write"])
    ).toBe("admin");
  });

  it("returns 'writer' when user has writer + reader but not admin", async () => {
    const { getRoleFromGroups } = await import("./roleAuthz.js");
    expect(getRoleFromGroups(["Wine Read-Only", "Wine Read-Write"])).toBe(
      "writer"
    );
  });

  it("supports comma-separated lists in each env var with whitespace", async () => {
    vi.stubEnv("IDENTITY_ROLE_ADMIN_GROUPS", " Wine Admin , Books Admin ");
    vi.stubEnv("IDENTITY_ROLE_WRITER_GROUPS", "");
    vi.stubEnv("IDENTITY_ROLE_READER_GROUPS", "");
    const { getRoleFromGroups } = await import("./roleAuthz.js");
    expect(getRoleFromGroups(["Books Admin"])).toBe("admin");
  });
});

// ---------------------------------------------------------------------------
// requireRole: no-op when nothing configured (RBAC not in use)
// ---------------------------------------------------------------------------

describe("requireRole — RBAC disabled (no role groups configured)", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.stubEnv("IDENTITY_ROLE_ADMIN_GROUPS", "");
    vi.stubEnv("IDENTITY_ROLE_WRITER_GROUPS", "");
    vi.stubEnv("IDENTITY_ROLE_READER_GROUPS", "");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("no-ops when identity is null and no role groups are configured", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() => requireRole("writer", null)).not.toThrow();
  });

  it("no-ops when identity has no groups and no role groups are configured", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() => requireRole("admin", identityFor([]))).not.toThrow();
  });

  it("no-ops when identity has groups but no role groups are configured", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("admin", identityFor(["whatever"]))
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// requireRole: enforcement when RBAC IS configured
// ---------------------------------------------------------------------------

describe("requireRole — RBAC enabled", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.stubEnv("IDENTITY_ROLE_ADMIN_GROUPS", "Wine Admin");
    vi.stubEnv("IDENTITY_ROLE_WRITER_GROUPS", "Wine Read-Write");
    vi.stubEnv("IDENTITY_ROLE_READER_GROUPS", "Wine Read-Only");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("throws InsufficientScopeError (→ 403) when identity is null", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() => requireRole("reader", null)).toThrow(InsufficientScopeError);
  });

  it("includes 'requires role' and tool name in the error message", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() => requireRole("writer", null, "add_bottle")).toThrow(
      /Tool 'add_bottle' requires role 'writer'/
    );
  });

  it("includes user's current role in the error message when they have one (lower tier)", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("writer", identityFor(["Wine Read-Only"]), "add_bottle")
    ).toThrow(/requires role 'writer'; you are 'reader'/);
  });

  it("throws when user matches no configured group at all", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("reader", identityFor(["Random Group"]))
    ).toThrow(/you are 'none'/);
  });

  it("allows when user's role equals the required role (reader = reader)", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("reader", identityFor(["Wine Read-Only"]))
    ).not.toThrow();
  });

  it("allows admin to call a writer-level tool", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("writer", identityFor(["Wine Admin"]))
    ).not.toThrow();
  });

  it("allows admin to call a reader-level tool", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("reader", identityFor(["Wine Admin"]))
    ).not.toThrow();
  });

  it("allows writer to call a reader-level tool", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("reader", identityFor(["Wine Read-Write"]))
    ).not.toThrow();
  });

  it("denies reader trying to call a writer-level tool", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("writer", identityFor(["Wine Read-Only"]))
    ).toThrow(InsufficientScopeError);
  });

  it("denies reader trying to call an admin-level tool", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("admin", identityFor(["Wine Read-Only"]))
    ).toThrow(InsufficientScopeError);
  });

  it("denies writer trying to call an admin-level tool", async () => {
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("admin", identityFor(["Wine Read-Write"]))
    ).toThrow(InsufficientScopeError);
  });

  it("partial config (only one tier set) still enables RBAC and enforces denials", async () => {
    vi.stubEnv("IDENTITY_ROLE_WRITER_GROUPS", "");
    vi.stubEnv("IDENTITY_ROLE_READER_GROUPS", "");
    // Only IDENTITY_ROLE_ADMIN_GROUPS set; writers/readers undefined.
    const { requireRole } = await import("./roleAuthz.js");
    expect(() =>
      requireRole("admin", identityFor(["not-an-admin"]))
    ).toThrow(InsufficientScopeError);
    expect(() =>
      requireRole("admin", identityFor(["Wine Admin"]))
    ).not.toThrow();
  });
});
