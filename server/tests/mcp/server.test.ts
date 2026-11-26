import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { describe, expect, it } from 'vitest';
import { openLensDb } from '../../src/db/lensDb.js';
import type { SinkDb } from '../../src/db/sinkDb.js';
import { assemblePlaybook } from '../../src/mcp/playbook/assemble.js';
import { createLensMcpServer, SERVER_INSTRUCTIONS } from '../../src/mcp/server.js';
import { seededSinkDb } from '../helpers.js';

async function connect({ sinkDb }: { sinkDb: SinkDb | null }) {
  const server = createLensMcpServer({
    lensDb: openLensDb(':memory:'),
    sinkDb,
    unifiMcp: { resolveClient: async () => null, getFirewallSummary: async () => null },
    homelabServices: {},
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.1.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

describe('lens MCP server', () => {
  it('serves instructions that point at the triage prompt and get_playbook', async () => {
    const client = await connect({ sinkDb: seededSinkDb([]) });
    const text = client.getInstructions();
    expect(text).toBe(SERVER_INSTRUCTIONS);
    expect(text).toMatch(/triage/);
    expect(text).toMatch(/get_playbook/);
  });

  it('triage prompt returns the assembled playbook', async () => {
    const client = await connect({ sinkDb: seededSinkDb([]) });
    expect((await client.listPrompts()).prompts.map((p) => p.name)).toContain('triage');
    const res = await client.getPrompt({ name: 'triage' });
    expect(res.messages).toHaveLength(1);
    expect(res.messages[0].role).toBe('user');
    expect((res.messages[0].content as { text: string }).text).toBe(assemblePlaybook());
  });

  it('get_playbook returns the same text', async () => {
    const client = await connect({ sinkDb: seededSinkDb([]) });
    const res = (await client.callTool({ name: 'get_playbook', arguments: {} })) as {
      content: { text: string }[];
    };
    expect(res.content[0].text).toBe(assemblePlaybook());
  });

  it('still serves the playbook with no sink DB (degraded mode)', async () => {
    const client = await connect({ sinkDb: null });
    expect(client.getInstructions()).toBe(SERVER_INSTRUCTIONS);
    expect((await client.getPrompt({ name: 'triage' })).messages).toHaveLength(1);
  });

  it('every lens tool the playbook names is registered', async () => {
    const client = await connect({ sinkDb: seededSinkDb([]) });
    const registered = new Set((await client.listTools()).tools.map((t) => t.name));
    const named = new Set(
      [...assemblePlaybook().matchAll(/`((?:get|submit|propose|list|mark)_[a-z_]+)`/g)].map((m) => m[1])
    );
    // list_clients belongs to the separate `unifi` MCP server, not the lens.
    named.delete('list_clients');
    expect(named.size).toBeGreaterThan(0);
    for (const n of named) expect(registered).toContain(n);
  });
});
