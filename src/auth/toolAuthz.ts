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

import type { Tool } from 'fastmcp';
import type { ToolParameters } from 'fastmcp';
import { identityContext } from './identityJwtVerifier.js';
import { type Role, requireRole } from './roleAuthz.js';
import type { IdentitySession } from './sessionAuth.js';

/**
 * Wrap a tool's execute() with a requireRole() gate. Returns a new tool
 * (same name/schema/description) whose execute enforces the role then runs
 * the original execute inside identityContext.
 */
export function withRequiredRole<P extends ToolParameters>(
  tool: Tool<IdentitySession | undefined, P>,
  required: Role,
): Tool<IdentitySession | undefined, P> {
  const originalExecute = tool.execute;
  return {
    ...tool,
    execute: async (args, context) => {
      const identity = context.session?.identity ?? null;
      requireRole(required, identity, tool.name);
      if (identity) {
        return identityContext.run(identity, () => originalExecute(args, context));
      }
      return originalExecute(args, context);
    },
  };
}
