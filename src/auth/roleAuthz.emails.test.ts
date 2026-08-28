/**
 * Email-tier RBAC (IDENTITY_ROLE_*_EMAILS).
 *
 * These exist because the Cloudflare MCP portal does not forward its
 * Cf-Access-Jwt-Assertion header upstream, so portal callers arrive with
 * `groups: []`. Email tiers are what make RBAC enforceable in that
 * topology — see the header comment in roleAuthz.ts.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Identity } from './identityJwtVerifier.js';

function identity(email: string, groups: string[] = []): Identity {
  return { email, sub: 'sub-1', groups };
}

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('email-tier resolution (IDENTITY_ROLE_*_EMAILS)', () => {
  it('maps each tier and is case/whitespace-insensitive', async () => {
    vi.stubEnv('IDENTITY_ROLE_ADMIN_EMAILS', ' Matthew@Example.com ');
    vi.stubEnv('IDENTITY_ROLE_WRITER_EMAILS', 'becky@example.com, kk@example.com');
    vi.stubEnv('IDENTITY_ROLE_READER_EMAILS', 'guest@example.com');
    const { getRoleFromEmail } = await import('./roleAuthz.js');

    expect(getRoleFromEmail('matthew@example.com')).toBe('admin');
    expect(getRoleFromEmail('  MATTHEW@example.COM ')).toBe('admin');
    expect(getRoleFromEmail('kk@example.com')).toBe('writer');
    expect(getRoleFromEmail('guest@example.com')).toBe('reader');
    expect(getRoleFromEmail('stranger@example.com')).toBeNull();
  });

  it('matches group names case-insensitively too', async () => {
    vi.stubEnv('IDENTITY_ROLE_ADMIN_GROUPS', 'Music Admin');
    vi.stubEnv('IDENTITY_ROLE_READER_GROUPS', ' music read-only ');
    const { getRoleFromGroups } = await import('./roleAuthz.js');

    expect(getRoleFromGroups(['MUSIC ADMIN'])).toBe('admin');
    expect(getRoleFromGroups(['music admin'])).toBe('admin');
    expect(getRoleFromGroups(['Music Read-Only'])).toBe('reader');
    expect(getRoleFromGroups([' Music Read-Only '])).toBe('reader');
    expect(getRoleFromGroups(['Music Something Else'])).toBeNull();
  });

  it('groups and email compose with highest-wins', async () => {
    vi.stubEnv('IDENTITY_ROLE_READER_GROUPS', 'Music Readers');
    vi.stubEnv('IDENTITY_ROLE_ADMIN_EMAILS', 'matthew@example.com');
    vi.stubEnv('IDENTITY_ROLE_WRITER_EMAILS', 'becky@example.com');
    const { getRoleForIdentity } = await import('./roleAuthz.js');

    // email admin beats group reader
    expect(getRoleForIdentity(identity('matthew@example.com', ['Music Readers']))).toBe('admin');
    // group reader alone
    expect(getRoleForIdentity(identity('nobody@example.com', ['Music Readers']))).toBe('reader');
    // email writer alone
    expect(getRoleForIdentity(identity('becky@example.com'))).toBe('writer');
    // group beats lower email tier
    vi.stubEnv('IDENTITY_ROLE_ADMIN_GROUPS', 'Music Admins');
    expect(getRoleForIdentity(identity('becky@example.com', ['Music Admins']))).toBe('admin');
  });

  it('resolves nothing when the identity matches neither source', async () => {
    vi.stubEnv('IDENTITY_ROLE_ADMIN_EMAILS', 'matthew@example.com');
    vi.stubEnv('IDENTITY_ROLE_READER_GROUPS', 'Music Readers');
    const { getRoleForIdentity } = await import('./roleAuthz.js');
    expect(getRoleForIdentity(identity('stranger@example.com', ['Other Group']))).toBeNull();
  });

  it('email-only config enables RBAC (fail-closed for unlisted identities)', async () => {
    vi.stubEnv('IDENTITY_ROLE_WRITER_EMAILS', 'becky@example.com');
    const { isRbacEnabled, requireRole } = await import('./roleAuthz.js');

    expect(isRbacEnabled()).toBe(true);
    expect(() => requireRole('reader', identity('becky@example.com'))).not.toThrow();
    expect(() => requireRole('reader', identity('stranger@example.com'), 'search')).toThrow(
      /no role is configured for stranger@example.com/,
    );
    expect(() =>
      requireRole('admin', identity('becky@example.com'), 'delete_release_rating'),
    ).toThrow(/requires role 'admin'; you are 'writer'/);
  });

  it('denies a null identity once any email list is configured', async () => {
    vi.stubEnv('IDENTITY_ROLE_READER_EMAILS', 'guest@example.com');
    const { requireRole } = await import('./roleAuthz.js');
    expect(() => requireRole('reader', null, 'search')).toThrow(/no identity on this request/);
  });

  it.each([
    'IDENTITY_ROLE_ADMIN_GROUPS',
    'IDENTITY_ROLE_WRITER_GROUPS',
    'IDENTITY_ROLE_READER_GROUPS',
    'IDENTITY_ROLE_ADMIN_EMAILS',
    'IDENTITY_ROLE_WRITER_EMAILS',
    'IDENTITY_ROLE_READER_EMAILS',
  ])('any single list (%s) is enough to enable RBAC', async (envVar) => {
    vi.stubEnv(envVar, 'something@example.com');
    const { isRbacEnabled } = await import('./roleAuthz.js');
    expect(isRbacEnabled()).toBe(true);
  });

  it('remains a no-op when none of the six lists is configured', async () => {
    const { isRbacEnabled, requireRole } = await import('./roleAuthz.js');
    expect(isRbacEnabled()).toBe(false);
    expect(() => requireRole('admin', null)).not.toThrow();
    expect(() => requireRole('admin', identity('anyone@example.com'))).not.toThrow();
  });

  it('treats empty and whitespace-only lists as unconfigured', async () => {
    vi.stubEnv('IDENTITY_ROLE_ADMIN_EMAILS', '   ');
    vi.stubEnv('IDENTITY_ROLE_READER_GROUPS', ' , , ');
    const { isRbacEnabled, requireRole } = await import('./roleAuthz.js');
    expect(isRbacEnabled()).toBe(false);
    expect(() => requireRole('admin', identity('anyone@example.com'))).not.toThrow();
  });
});
