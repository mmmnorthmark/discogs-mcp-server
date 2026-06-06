/**
 * Per-tool role authorization wrapper for FastMCP tools.
 *
 * Each tool is tagged with a required role (reader/writer/admin) in the
 * central TOOL_ROLES dispatch table (src/tools/toolRoles.ts). At registration
 * time we wrap every tool's `execute` so that:
 *
 *   1. requireRole(role, identity, toolName) runs FIRST. When RBAC is
 *      configured via IDENTITY_ROLE_*_GROUPS env vars, this throws
 *      InsufficientScopeError (mapped by the MCP SDK to HTTP 403) if the
 *      caller's role is insufficient. When no RBAC env vars are set,
 *      requireRole is a no-op and existing single-tenant deployments are
 *      unaffected.
 *
 *   2. The original execute runs inside identityContext.run() so any
 *      downstream code that reads identityContext.getStore() sees the
 *      verified identity. This keeps the AsyncLocalStorage path live
 *      (matching cellartracker-mcp behavior) even though FastMCP passes
 *      identity explicitly through the session object.
 */

import type { Tool, ToolParameters } from 'fastmcp';
import type { FastMCPSessionAuth } from '../types/common.js';
import { DEFAULT_TOOL_ROLE, TOOL_ROLES } from '../tools/toolRoles.js';
import { type Identity, identityContext } from './identityJwtVerifier.js';
import { type Role, requireRole } from './roleAuthz.js';

/**
 * Read the verified identity (if any) out of FastMCP's session bag.
 * sessionAuth.identityAuthenticate stores it under `identity`; everything
 * else is null. Safe across deployments that haven't configured an
 * identity gateway (returns null).
 */
function extractIdentity(session: FastMCPSessionAuth): Identity | null {
  const candidate = session?.identity;
  if (!candidate || typeof candidate !== 'object') return null;
  const ident = candidate as Partial<Identity>;
  if (typeof ident.email !== 'string' || typeof ident.sub !== 'string') return null;
  return {
    email: ident.email,
    sub: ident.sub,
    groups: Array.isArray(ident.groups) ? ident.groups.filter((g) => typeof g === 'string') : [],
  };
}

/**
 * Wrap a tool's execute() with a requireRole() gate. Returns a new tool
 * (same name/schema/description) whose execute enforces the role then runs
 * the original execute inside identityContext.
 *
 * Uses FastMCP's native session type so the wrapped tool stays
 * assignment-compatible with server.addTool(...) call sites that use the
 * library's default generic.
 */
export function withRequiredRole<P extends ToolParameters>(
  tool: Tool<FastMCPSessionAuth, P>,
  required: Role,
): Tool<FastMCPSessionAuth, P> {
  const originalExecute = tool.execute;
  return {
    ...tool,
    execute: async (args, context) => {
      const identity = extractIdentity(context.session);
      requireRole(required, identity, tool.name);
      if (identity) {
        return identityContext.run(identity, () => originalExecute(args, context));
      }
      return originalExecute(args, context);
    },
  };
}

/**
 * Convenience wrapper that looks up the tool's required role in the
 * central TOOL_ROLES dispatch table. Unknown tools default to `writer`
 * (DEFAULT_TOOL_ROLE) — safer than `reader` for an unrecognized mutation.
 *
 * Use this at registration time:
 *
 *   server.addTool(protectTool(getReleaseTool));
 */
export function protectTool<P extends ToolParameters>(
  tool: Tool<FastMCPSessionAuth, P>,
): Tool<FastMCPSessionAuth, P> {
  const required = TOOL_ROLES[tool.name] ?? DEFAULT_TOOL_ROLE;
  return withRequiredRole(tool, required);
}
