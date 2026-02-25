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
  it('exposes public tools with the music prefix', () => {
    const toolNames = collectRegisteredToolNames({ toolNamePrefix: 'music' });

    expect(toolNames).toContain('music-search');
    expect(toolNames).toContain('music-get_release');
    expect(toolNames).not.toContain('search');
    expect(toolNames.every((toolName) => toolName.startsWith('music-'))).toBe(true);
  });

  it('can expose unprefixed tools when the prefix is empty', () => {
    const toolNames = collectRegisteredToolNames({ toolNamePrefix: '' });

    expect(toolNames).toContain('search');
    expect(toolNames).not.toContain('music-search');
  });
});
