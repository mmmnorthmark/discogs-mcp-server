import type { FastMCP, Tool } from 'fastmcp';
import { describe, expect, it } from 'vitest';
import { protectTool } from '../../src/auth/toolAuthz.js';
import { registerTools } from '../../src/tools/index.js';
import { TOOL_RISK, UNKNOWN_TOOL_RISK, getToolRisk } from '../../src/tools/toolRisk.js';
import type { FastMCPSessionAuth } from '../../src/types/common.js';

function collectRegistered(options?: Parameters<typeof registerTools>[1]) {
  const tools: Tool<FastMCPSessionAuth, never>[] = [];
  const server = {
    addTool: (tool: Tool<FastMCPSessionAuth, never>): void => {
      tools.push(tool);
    },
  } as unknown as FastMCP;

  registerTools(server, options);

  return tools;
}

describe('TOOL_RISK table', () => {
  it('classifies every registered tool', () => {
    const unclassified = collectRegistered()
      .map((tool) => tool.name)
      .filter((name) => !(name in TOOL_RISK));

    expect(unclassified).toEqual([]);
  });

  it('holds the read-only invariant: read-only implies reader and non-destructive', () => {
    const violations = Object.entries(TOOL_RISK)
      .filter(([, risk]) => risk.readOnly && (risk.role !== 'reader' || risk.destructive))
      .map(([name]) => name);

    expect(violations).toEqual([]);
  });

  it('requires admin for every destructive tool', () => {
    const violations = Object.entries(TOOL_RISK)
      .filter(([, risk]) => risk.destructive && risk.role !== 'admin')
      .map(([name]) => name);

    expect(violations).toEqual([]);
  });

  it('denies by default for unclassified tools', () => {
    expect(getToolRisk('some_tool_nobody_classified')).toBe(UNKNOWN_TOOL_RISK);
    expect(UNKNOWN_TOOL_RISK.role).toBe('admin');
    expect(UNKNOWN_TOOL_RISK.readOnly).toBe(false);
    expect(UNKNOWN_TOOL_RISK.destructive).toBe(true);
  });
});

describe('Read-only mode derives from TOOL_RISK', () => {
  it('registers exactly the read-only tools', () => {
    const registered = collectRegistered({ readOnly: true }).map((tool) => tool.name);
    const expected = Object.entries(TOOL_RISK)
      .filter(([, risk]) => risk.readOnly)
      .map(([name]) => name);

    expect(registered.sort()).toEqual(expected.sort());
  });

  it('registers strictly more tools when writes are enabled', () => {
    const readWrite = collectRegistered().length;
    const readOnly = collectRegistered({ readOnly: true }).length;

    expect(readOnly).toBeLessThan(readWrite);
  });

  it('excludes every destructive tool', () => {
    const registered = collectRegistered({ readOnly: true }).map((tool) => tool.name);

    expect(registered).not.toContain('delete_marketplace_listing');
    expect(registered).not.toContain('delete_release_from_user_collection_folder');
    expect(registered).not.toContain('edit_user_collection_custom_field_value');
  });
});

describe('MCP annotations', () => {
  it('attaches annotations matching the risk profile', () => {
    for (const tool of collectRegistered()) {
      const risk = getToolRisk(tool.name);
      expect(tool.annotations, `${tool.name} has no annotations`).toBeDefined();
      expect(tool.annotations).toMatchObject({
        readOnlyHint: risk.readOnly,
        destructiveHint: risk.destructive,
        idempotentHint: risk.idempotent,
        openWorldHint: risk.openWorld,
      });
    }
  });

  it('marks a search read-only and a delete destructive', () => {
    const byName = new Map(collectRegistered().map((tool) => [tool.name, tool]));

    expect(byName.get('search')?.annotations).toMatchObject({
      readOnlyHint: true,
      destructiveHint: false,
    });
    expect(byName.get('delete_marketplace_listing')?.annotations).toMatchObject({
      readOnlyHint: false,
      destructiveHint: true,
    });
  });

  it('lets a tool override an annotation locally', () => {
    const tool = {
      name: 'search',
      description: 'x',
      annotations: { openWorldHint: true },
      execute: async () => 'ok',
    } as unknown as Tool<FastMCPSessionAuth, never>;

    expect(protectTool(tool).annotations).toMatchObject({
      readOnlyHint: true,
      openWorldHint: true,
    });
  });
});
