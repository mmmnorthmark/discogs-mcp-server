/**
 * End-to-end per-tool RBAC enforcement: a caller's identity, resolved
 * through the email/group tiers, gated against each tool's TOOL_RISK
 * role by protectTool().
 *
 * Two harnesses, deliberately:
 *   - DENIAL cases run the REAL registered tools. requireRole throws
 *     before the wrapped execute runs, so this exercises the actual
 *     registration wiring with no network access.
 *   - ALLOW cases use a stub execute under a real tool name, so a
 *     permitted call proves the gate opened without calling Discogs.
 */
import type { FastMCP, Tool } from 'fastmcp';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import type { FastMCPSessionAuth } from '../../src/types/common.js';

const ADMIN = 'matthew@example.com';
const WRITER = 'becky@example.com';
const READER = 'guest@example.com';

function session(email: string, groups: string[] = []): FastMCPSessionAuth {
  return { identity: { email, sub: `sub-${email}`, groups } } as unknown as FastMCPSessionAuth;
}

/** Execute a tool the way FastMCP does, with an authenticated session. */
async function call(
  tool: Tool<FastMCPSessionAuth, never>,
  auth: FastMCPSessionAuth,
): Promise<unknown> {
  const context = { session: auth, log: console, reportProgress: async () => {} };
  return (tool.execute as (a: unknown, c: unknown) => Promise<unknown>)({}, context);
}

async function registeredTool(name: string): Promise<Tool<FastMCPSessionAuth, never>> {
  const { registerTools } = await import('../../src/tools/index.js');
  const tools: Tool<FastMCPSessionAuth, never>[] = [];
  const server = {
    addTool: (tool: Tool<FastMCPSessionAuth, never>): void => {
      tools.push(tool);
    },
  } as unknown as FastMCP;
  registerTools(server);
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`tool not registered: ${name}`);
  return tool;
}

/** A tool carrying a real name (so TOOL_RISK resolves) but a stub body. */
async function stubTool(name: string): Promise<Tool<FastMCPSessionAuth, never>> {
  const { protectTool } = await import('../../src/auth/toolAuthz.js');
  return protectTool({
    name,
    description: 'stub',
    parameters: z.object({}),
    execute: async () => 'STUB_OK',
  } as unknown as Tool<FastMCPSessionAuth, never>) as Tool<FastMCPSessionAuth, never>;
}

beforeEach(() => {
  vi.resetModules();
  vi.stubEnv('IDENTITY_ROLE_ADMIN_EMAILS', ADMIN);
  vi.stubEnv('IDENTITY_ROLE_WRITER_EMAILS', WRITER);
  vi.stubEnv('IDENTITY_ROLE_READER_EMAILS', READER);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('RBAC enforcement through protectTool (real registered tools)', () => {
  it('denies a reader the writer-level create_marketplace_listing', async () => {
    const tool = await registeredTool('create_marketplace_listing');
    await expect(call(tool, session(READER))).rejects.toThrow(
      /requires role 'writer'; you are 'reader'/,
    );
  });

  it.each([
    'delete_marketplace_listing',
    'delete_release_from_user_collection_folder',
    'delete_user_collection_folder',
    'delete_item_in_wantlist',
    'delete_release_rating',
  ])('denies a writer the admin-only %s', async (name) => {
    const tool = await registeredTool(name);
    await expect(call(tool, session(WRITER))).rejects.toThrow(
      /requires role 'admin'; you are 'writer'/,
    );
  });

  it('denies a reader an admin-only delete tool', async () => {
    const tool = await registeredTool('delete_user_collection_folder');
    await expect(call(tool, session(READER))).rejects.toThrow(
      /requires role 'admin'; you are 'reader'/,
    );
  });

  it('denies an identity that matches no configured tier at all', async () => {
    const tool = await registeredTool('search');
    await expect(call(tool, session('stranger@example.com'))).rejects.toThrow(
      /no role is configured for stranger@example.com/,
    );
  });

  it('denies a request carrying no identity', async () => {
    const tool = await registeredTool('search');
    await expect(call(tool, {} as FastMCPSessionAuth)).rejects.toThrow(
      /no identity on this request/,
    );
  });
});

describe('RBAC enforcement — permitted calls reach the tool body', () => {
  it('lets a reader call the read-only search', async () => {
    const tool = await stubTool('search');
    await expect(call(tool, session(READER))).resolves.toBe('STUB_OK');
  });

  it('lets a writer call a writer-level tool', async () => {
    const tool = await stubTool('create_marketplace_listing');
    await expect(call(tool, session(WRITER))).resolves.toBe('STUB_OK');
  });

  it('lets an admin call every tier', async () => {
    for (const name of ['search', 'create_marketplace_listing', 'delete_user_collection_folder']) {
      const tool = await stubTool(name);
      await expect(call(tool, session(ADMIN))).resolves.toBe('STUB_OK');
    }
  });

  it('grants access via group membership when the email is unlisted', async () => {
    vi.stubEnv('IDENTITY_ROLE_WRITER_GROUPS', 'Music Writers');
    const tool = await stubTool('create_marketplace_listing');
    await expect(call(tool, session('nobody@example.com', ['Music Writers']))).resolves.toBe(
      'STUB_OK',
    );
  });

  it('takes the highest tier when group and email disagree', async () => {
    vi.stubEnv('IDENTITY_ROLE_READER_GROUPS', 'Music Readers');
    // ADMIN by email, reader by group → admin wins, so a delete succeeds.
    const tool = await stubTool('delete_user_collection_folder');
    await expect(call(tool, session(ADMIN, ['Music Readers']))).resolves.toBe('STUB_OK');
  });
});

describe('RBAC disabled (no role lists configured)', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it('allows an unknown identity to call an admin-level tool', async () => {
    const tool = await stubTool('delete_user_collection_folder');
    await expect(call(tool, session('anyone@example.com'))).resolves.toBe('STUB_OK');
  });

  it('allows a request with no identity at all', async () => {
    const tool = await stubTool('search');
    await expect(call(tool, {} as FastMCPSessionAuth)).resolves.toBe('STUB_OK');
  });
});
