/**
 * Role-based per-tool authorization, driven by identity-gateway group
 * memberships and/or per-email allowlists.
 *
 * Role tiers (highest → lowest):
 *   admin  > writer > reader
 *
 * Higher tiers satisfy any lower-tier requirement (admin can call
 * writer/reader tools; writer can call reader tools).
 *
 * Configuration (env vars, read at call time so redeploys propagate
 * without a restart):
 *   IDENTITY_ROLE_ADMIN_GROUPS   Comma-separated group names → `admin`.
 *   IDENTITY_ROLE_WRITER_GROUPS  Comma-separated group names → `writer`.
 *   IDENTITY_ROLE_READER_GROUPS  Comma-separated group names → `reader`.
 *   IDENTITY_ROLE_ADMIN_EMAILS   Comma-separated emails → `admin`.
 *   IDENTITY_ROLE_WRITER_EMAILS  Comma-separated emails → `writer`.
 *   IDENTITY_ROLE_READER_EMAILS  Comma-separated emails → `reader`.
 *
 * WHY EMAIL TIERS EXIST. Group-driven RBAC needs a gateway to forward its
 * signed identity JWT to the origin. Empirical testing (2026-08-28) showed
 * the Cloudflare MCP portal does NOT forward Cf-Access-Jwt-Assertion
 * upstream, so portal traffic reaches us as an OAuth Bearer caller whose
 * identity carries `groups: []` (see sessionAuth.ts). With groups-only
 * RBAC, enabling role lists would 403 every portal user. Email tiers key
 * off the one claim we reliably have — the verified email — so RBAC can be
 * enforced behind a portal with no identity plumbing at all.
 *
 * Matching is case-insensitive and whitespace-trimmed on BOTH sides for
 * BOTH sources. Group names come from directory systems that do not agree
 * on casing, and email domains are case-insensitive by definition; a
 * case-sensitive compare denies a legitimate user and is a nuisance to
 * debug.
 *
 * If NONE of the six lists is configured, requireRole is a no-op (RBAC not
 * in use, allow all). This preserves behavior for deployments with no
 * identity gateway. Once ANY list is configured, resolution is FAIL-CLOSED:
 * an identity matching no list gets no tools.
 *
 * Throws InsufficientScopeError on denial — the MCP SDK's bearer-auth
 * middleware maps that to HTTP 403 with a clear reason in the message.
 */

import { InsufficientScopeError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { Identity } from './identityJwtVerifier.js';

export type Role = 'admin' | 'writer' | 'reader';

// Higher number = more privileged. admin (3) ≥ writer (2) ≥ reader (1).
const ROLE_TIER: Record<Role, number> = {
  admin: 3,
  writer: 2,
  reader: 1,
};

/**
 * Split a comma-separated env var into normalized entries: trimmed,
 * lowercased, empties dropped. Used for both group and email lists so the
 * two sources cannot drift in their matching semantics.
 */
function parseList(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);
}

interface RoleConfig {
  admin: string[];
  writer: string[];
  reader: string[];
  adminEmails: string[];
  writerEmails: string[];
  readerEmails: string[];
}

function loadConfig(): RoleConfig {
  return {
    admin: parseList(process.env.IDENTITY_ROLE_ADMIN_GROUPS),
    writer: parseList(process.env.IDENTITY_ROLE_WRITER_GROUPS),
    reader: parseList(process.env.IDENTITY_ROLE_READER_GROUPS),
    adminEmails: parseList(process.env.IDENTITY_ROLE_ADMIN_EMAILS),
    writerEmails: parseList(process.env.IDENTITY_ROLE_WRITER_EMAILS),
    readerEmails: parseList(process.env.IDENTITY_ROLE_READER_EMAILS),
  };
}

function isRbacConfigured(config: RoleConfig): boolean {
  return (
    config.admin.length > 0 ||
    config.writer.length > 0 ||
    config.reader.length > 0 ||
    config.adminEmails.length > 0 ||
    config.writerEmails.length > 0 ||
    config.readerEmails.length > 0
  );
}

/**
 * Resolve the HIGHEST role the user qualifies for from their group
 * memberships. Returns null if the user matches no configured role group.
 *
 * Higher-tier matches win: a user in both an admin group and a reader
 * group resolves to `admin`. Comparison is case-insensitive.
 */
export function getRoleFromGroups(groups: string[]): Role | null {
  const config = loadConfig();
  const held = new Set(groups.map((group) => group.trim().toLowerCase()));
  const inSet = (set: string[]): boolean => set.some((group) => held.has(group));

  if (inSet(config.admin)) return 'admin';
  if (inSet(config.writer)) return 'writer';
  if (inSet(config.reader)) return 'reader';
  return null;
}

/**
 * Resolve a role from the email allowlists (IDENTITY_ROLE_*_EMAILS).
 * Comparison is lowercase/trimmed on both sides. Highest tier wins.
 */
export function getRoleFromEmail(email: string): Role | null {
  const config = loadConfig();
  const needle = email.trim().toLowerCase();
  if (config.adminEmails.includes(needle)) return 'admin';
  if (config.writerEmails.includes(needle)) return 'writer';
  if (config.readerEmails.includes(needle)) return 'reader';
  return null;
}

/**
 * Full identity resolution: groups and email are both consulted, and when
 * both match the HIGHEST tier wins (admin > writer > reader). Null when
 * the identity matches no configured list.
 */
export function getRoleForIdentity(identity: Identity): Role | null {
  const fromGroups = getRoleFromGroups(identity.groups);
  const fromEmail = getRoleFromEmail(identity.email);
  if (!fromGroups) return fromEmail;
  if (!fromEmail) return fromGroups;
  return ROLE_TIER[fromGroups] >= ROLE_TIER[fromEmail] ? fromGroups : fromEmail;
}

/** True once any of the six role lists is configured. */
export function isRbacEnabled(): boolean {
  return isRbacConfigured(loadConfig());
}

/**
 * Enforce a minimum role for the current request.
 *
 * Behavior:
 * - If NONE of the six role lists is configured (RBAC not in use), no-op
 *   and allow the call.
 * - Otherwise: throw InsufficientScopeError (→ HTTP 403) if identity is
 *   null, if the identity matches no configured list (fail-closed), or if
 *   the resolved role is lower than `required`.
 *
 * The InsufficientScopeError message names the required role and the
 * user's actual role for actionable debugging.
 */
export function requireRole(required: Role, identity: Identity | null, toolName?: string): void {
  const config = loadConfig();
  if (!isRbacConfigured(config)) return;

  const where = toolName ? `Tool '${toolName}'` : `This operation`;

  if (!identity) {
    throw new InsufficientScopeError(
      `${where} requires role '${required}'; no identity on this request`,
    );
  }

  const actual = getRoleForIdentity(identity);
  if (!actual) {
    // Fail closed: role lists ARE configured and this identity matches
    // none of them — no tools, with an actionable message.
    throw new InsufficientScopeError(
      `${where} requires role '${required}'; no role is configured for ${identity.email}. ` +
        `Add the email to IDENTITY_ROLE_{ADMIN,WRITER,READER}_EMAILS (or a mapped group) ` +
        `on this deployment.`,
    );
  }
  if (ROLE_TIER[actual] < ROLE_TIER[required]) {
    throw new InsufficientScopeError(`${where} requires role '${required}'; you are '${actual}'`);
  }
}
