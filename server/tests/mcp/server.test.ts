import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { describe, expect, it } from 'vitest';
import { type LensDb, openLensDb } from '../../src/db/lensDb.js';
import { humanChange, listEntries } from '../../src/db/playbookStore.js';
import type { EventsDb } from '../../src/db/eventsDb.js';
import { assemblePlaybook } from '../../src/mcp/playbook/assemble.js';
import { PLAYBOOK_DEFAULTS } from '../../src/mcp/playbook/defaults.js';
import { seedPlaybookDefaults } from '../../src/mcp/playbook/seed.js';
import { createMcpServer, type McpDeps, SERVER_INSTRUCTIONS } from '../../src/mcp/server.js';
import { UNIFI_ONLY_TOOLS } from '../../src/mcp/playbook/core.js';
import { seededEventsDb, stubUnifiClient } from '../helpers.js';

async function connect({
  eventsDb = seededEventsDb([]),
  lensDb = openLensDb(':memory:'),
  unifi = null,
}: {
  eventsDb?: EventsDb;
  lensDb?: LensDb;
  unifi?: McpDeps['unifi'];
}) {
  const server = createMcpServer({
    lensDb,
    eventsDb,
    unifi,
    enricher: { resolveClient: async () => null, getFirewallSummary: async () => null },
    homelabServices: {},
  }, { trustedAdminNames: ['alice'] });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.1.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

describe('MCP server', () => {
  it('lists the event tools: list_events, get_event, get_categories, get_event_stats', async () => {
    const names = (await (await connect({})).listTools()).tools.map((t) => t.name);
    for (const n of ['list_events', 'get_event', 'get_categories', 'get_event_stats']) {
      expect(names).toContain(n);
    }
  });

  it('has no duplicate tool names', async () => {
    const names = (await (await connect({})).listTools()).tools.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it('identifies itself as unifi-power-tools', async () => {
    expect((await connect({})).getServerVersion()?.name).toBe('unifi-power-tools');
  });

  it('serves instructions that point at the triage prompt and get_playbook', async () => {
    const client = await connect({ eventsDb: seededEventsDb([]) });
    const text = client.getInstructions();
    expect(text).toBe(SERVER_INSTRUCTIONS);
    expect(text).toMatch(/triage/);
    expect(text).toMatch(/get_playbook/);
  });

  it('triage prompt returns the assembled playbook', async () => {
    const client = await connect({ eventsDb: seededEventsDb([]) });
    expect((await client.listPrompts()).prompts.map((p) => p.name)).toContain('triage');
    const res = await client.getPrompt({ name: 'triage' });
    expect(res.messages).toHaveLength(1);
    expect(res.messages[0].role).toBe('user');
    expect((res.messages[0].content as { text: string }).text).toBe(assemblePlaybook({ trustedAdminNames: ['alice'], entries: [] }));
  });

  it('get_playbook returns the same text', async () => {
    const client = await connect({ eventsDb: seededEventsDb([]) });
    const res = (await client.callTool({ name: 'get_playbook', arguments: {} })) as {
      content: { text: string }[];
    };
    expect(res.content[0].text).toBe(assemblePlaybook({ trustedAdminNames: ['alice'], entries: [] }));
  });

  it('serves the configured trusted admins in the playbook', async () => {
    const client = await connect({ eventsDb: seededEventsDb([]) });
    const res = (await client.callTool({ name: 'get_playbook', arguments: {} })) as {
      content: { text: string }[];
    };
    expect(res.content[0].text).toMatch(/## Configured trusted admins[\s\S]*- alice/);
  });

  it('serves instructions and the triage prompt from an empty events DB', async () => {
    const client = await connect({});
    expect(client.getInstructions()).toBe(SERVER_INSTRUCTIONS);
    expect((await client.getPrompt({ name: 'triage' })).messages).toHaveLength(1);
  });

  async function playbookText(client: Client) {
    const res = (await client.callTool({ name: 'get_playbook', arguments: {} })) as {
      content: { text: string }[];
    };
    return res.content[0].text;
  }

  it('serves an entry accepted after the server was built', async () => {
    const lensDb = openLensDb(':memory:');
    const client = await connect({ eventsDb: seededEventsDb([]), lensDb });
    expect(await playbookText(client)).not.toContain('### [');

    const { entry } = humanChange(
      lensDb,
      { op: 'add', title: 'Late entry', body: 'late body' },
      '2026-01-01T00:00:00.000Z'
    );
    expect(await playbookText(client)).toContain(`### [${entry.id}] Late entry\n\nlate body`);
    const prompt = await client.getPrompt({ name: 'triage' });
    expect((prompt.messages[0].content as { text: string }).text).toContain(`### [${entry.id}]`);

    humanChange(lensDb, { op: 'retire', entry_id: entry.id }, '2026-01-02T00:00:00.000Z');
    expect(await playbookText(client)).not.toContain('### [');
  });

  it('marks entries that are still shipped default text', async () => {
    const lensDb = openLensDb(':memory:');
    seedPlaybookDefaults(lensDb, PLAYBOOK_DEFAULTS.slice(0, 2), '2026-01-01T00:00:00.000Z');
    const [first, second] = listEntries(lensDb);
    humanChange(
      lensDb,
      { op: 'edit', entry_id: second.id, title: 'Mine', body: 'my text' },
      '2026-01-02T00:00:00.000Z'
    );
    const text = await playbookText(await connect({ lensDb }));
    expect(text).toContain(`### [${first.id}] ${first.title} (default)\n\n`);
    expect(text).toContain(`### [${second.id}] Mine\n\n`);
  });

  function namedTools() {
    return new Set(
      [
        ...assemblePlaybook({ trustedAdminNames: ['alice'], entries: [] }).matchAll(
          /`((?:get|submit|propose|list|mark)_[a-z_]+)`/g
        ),
      ].map((m) => m[1])
    );
  }

  it('with UniFi off, every always-on tool the playbook names is registered and UniFi-only ones are not', async () => {
    const registered = new Set((await (await connect({})).listTools()).tools.map((t) => t.name));
    const named = namedTools();
    expect(named.size).toBeGreaterThan(0);
    for (const n of named) {
      if ((UNIFI_ONLY_TOOLS as readonly string[]).includes(n)) expect(registered).not.toContain(n);
      else expect(registered).toContain(n);
    }
  });

  it('with UniFi configured, every tool the playbook names is registered', async () => {
    const client = await connect({ unifi: { client: stubUnifiClient, allowWrites: false } });
    const registered = new Set((await client.listTools()).tools.map((t) => t.name));
    for (const n of namedTools()) expect(registered).toContain(n);
    expect(registered).not.toContain('delete_firewall_rule');
  });

  it('never tells triage to use a write tool', () => {
    const text = assemblePlaybook({ trustedAdminNames: [], entries: [] });
    expect(text).toMatch(/Never call UniFi write tools/);
    expect(text).not.toMatch(/the `unifi` MCP server/);
  });
});
