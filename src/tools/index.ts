import type { FastMCP } from 'fastmcp';
import { registerDatabaseTools } from './database.js';
import { registerInventoryExportTool } from './inventoryExport.js';
import { registerMarketplaceTools } from './marketplace.js';
import { registerMediaTools } from './media.js';
import { registerUserCollectionTools } from './userCollection.js';
import { registerUserIdentityTools } from './userIdentity.js';
import { registerUserListsTools } from './userLists.js';
import { registerUserWantlistTools } from './userWantlist.js';

export interface ToolRegistrationOptions {
  readOnly?: boolean;
  toolNamePrefix?: string;
}

function normalizeToolNamePrefix(prefix: string | undefined): string | undefined {
  const trimmedPrefix = prefix?.trim();

  if (!trimmedPrefix) {
    return undefined;
  }

  return trimmedPrefix.replace(/-+$/u, '');
}

function withToolNamePrefix(server: FastMCP, toolNamePrefix: string | undefined): FastMCP {
  const normalizedPrefix = normalizeToolNamePrefix(toolNamePrefix);

  if (!normalizedPrefix) {
    return server;
  }

  return {
    addTool: (tool: Parameters<FastMCP['addTool']>[0]): void => {
      const prefixedName = tool.name.startsWith(`${normalizedPrefix}-`)
        ? tool.name
        : `${normalizedPrefix}-${tool.name}`;

      server.addTool({
        ...tool,
        name: prefixedName,
      });
    },
  } as FastMCP;
}

/**
 * Registers all MCP tools with the server
 * @param server The FastMCP server instance
 * @param options Registration options (e.g. readOnly mode)
 */
export function registerTools(server: FastMCP, options?: ToolRegistrationOptions): void {
  const publicServer = withToolNamePrefix(server, options?.toolNamePrefix);

  registerDatabaseTools(publicServer, options);
  registerMarketplaceTools(publicServer, options);
  registerInventoryExportTool(publicServer, options);
  registerUserIdentityTools(publicServer, options);
  registerUserCollectionTools(publicServer, options);
  registerUserWantlistTools(publicServer, options);
  registerUserListsTools(publicServer, options);
  registerMediaTools(publicServer, options);
}
