import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { describe, expect, it } from 'vitest';
import { allUnifiTools, registerUnifiTools } from '../../src/unifi/tools/index.js';
import { stubUnifiClient } from '../helpers.js';


const WRITEY = /^(create|update|delete|block|unblock|set|remove)_/;

async function listed(allowWrites: boolean) {
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  registerUnifiTools(server, allUnifiTools(stubUnifiClient), { allowWrites });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return (await client.listTools()).tools;
}

describe('UniFi tool registration', () => {
  const tools = allUnifiTools(stubUnifiClient);

  it('every tool declares readOnly explicitly', () => {
    for (const t of tools) expect(typeof t.readOnly, t.name).toBe('boolean');
  });

  it('every create_/update_/delete_/block_/unblock_/set_/remove_ tool is a write', () => {
    for (const t of tools) if (WRITEY.test(t.name)) expect(t.readOnly, t.name).toBe(false);
    // A tool added or dropped later shows up as a failing count.
    expect(tools.filter((t) => WRITEY.test(t.name)).length).toBe(22);
    expect(tools.length).toBe(37);
  });

  it('registers no write tool when allowWrites is false', async () => {
    const names = (await listed(false)).map((t) => t.name);
    expect(names.some((n) => WRITEY.test(n))).toBe(false);
    expect(names).toContain('list_clients');
    expect(names).toHaveLength(tools.filter((t) => t.readOnly).length);
  });

  it('registers write tools with destructiveHint when allowWrites is true', async () => {
    const listedTools = await listed(true);
    const del = listedTools.find((t) => t.name === 'delete_firewall_rule');
    expect(del?.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true });
    const read = listedTools.find((t) => t.name === 'list_clients');
    expect(read?.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false });
    expect(listedTools).toHaveLength(37);
  });
});
