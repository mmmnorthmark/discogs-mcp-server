/**
 * Single registration path for every tool.
 *
 * Both access decisions are made here from the central TOOL_RISK table, so
 * no tool file decides for itself whether it is a mutation:
 *
 *   - Read-only deployments (READONLY_MODE=true) register only tools whose
 *     risk profile says readOnly. Excluded tools are absent from the tool
 *     list entirely, so a client never sees them and cannot be talked into
 *     calling them — a stronger guarantee than failing at call time.
 *   - Every registered tool is wrapped by protectTool(), which applies the
 *     role gate and attaches MCP annotations.
 */

import type { FastMCP, Tool, ToolParameters } from 'fastmcp';
import type { FastMCPSessionAuth } from '../types/common.js';
import { protectTool } from '../auth/toolAuthz.js';
import { getToolRisk } from './toolRisk.js';

export interface ToolRegistrationOptions {
  readOnly?: boolean;
}

/**
 * Register one tool, unless read-only mode excludes it.
 * Returns true when the tool was registered.
 */
export function register<P extends ToolParameters>(
  server: FastMCP,
  tool: Tool<FastMCPSessionAuth, P>,
  options?: ToolRegistrationOptions,
): boolean {
  if (options?.readOnly && !getToolRisk(tool.name).readOnly) {
    return false;
  }

  server.addTool(protectTool(tool));
  return true;
}
