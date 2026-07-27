import type { FastMCP } from 'fastmcp';
import { describe, expect, it } from 'vitest';
import { registerTools } from '../../src/tools/index.js';

function collectRegisteredToolNames(options?: Parameters<typeof registerTools>[1]): string[] {
  const toolNames: string[] = [];
  const server = {
    addTool: (tool: Parameters<FastMCP['addTool']>[0]): void => {
      toolNames.push(tool.name);
    },
  } as FastMCP;

  registerTools(server, options);

  return toolNames;
}

describe('Tool registration', () => {
  it('registers tools under their unprefixed names', () => {
    const toolNames = collectRegisteredToolNames();

    expect(toolNames).toContain('search');
    expect(toolNames).toContain('get_release');
  });

  it('omits mutating tools in read-only mode', () => {
    const readWrite = collectRegisteredToolNames();
    const readOnly = collectRegisteredToolNames({ readOnly: true });

    expect(readOnly.length).toBeLessThan(readWrite.length);
    expect(readOnly).toContain('search');
    expect(readOnly).not.toContain('delete_marketplace_listing');
    expect(readOnly).not.toContain('edit_user_collection_custom_field_value');
  });
});
