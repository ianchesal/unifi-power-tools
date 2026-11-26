import { DatabaseSync } from 'node:sqlite';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { describe, expect, it } from 'vitest';
import { applyTrigger, type Finding } from '../../src/analysis/findings.js';
import { queueForAnalysis } from '../../src/analysis/pipeline.js';
import { getAnalysisRequest } from '../../src/db/analysisRequestsStore.js';
import { getFindingById, upsertFinding } from '../../src/db/findingsStore.js';
import { type LensDb, openLensDb } from '../../src/db/lensDb.js';
import { humanChange, listEntries } from '../../src/db/playbookStore.js';
import type { SinkDb } from '../../src/db/sinkDb.js';
import { PLAYBOOK_DEFAULTS } from '../../src/mcp/playbook/defaults.js';
import { seedPlaybookDefaults } from '../../src/mcp/playbook/seed.js';
import { registerAnalysisTools } from '../../src/mcp/tools.js';
import { seededSinkDb } from '../helpers.js';

const IP = '198.51.100.4';
const MAC = 'aa:aa:aa:aa:aa:01';
// Recent enough to fall inside the never-decided lookback from "now".
const FIRST_SEEN = new Date(Date.now() - 60 * 60 * 1000).toISOString();
const RECENT = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();

async function connectedClient(lensDb: LensDb, sinkDb: SinkDb | null) {
  const server = new McpServer({ name: 'test', version: '0.1.0' });
  registerAnalysisTools(server, {
    lensDb,
    sinkDb,
    unifiMcp: { resolveClient: async () => null, getFirewallSummary: async () => null },
    homelabServices: {},
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.1.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

type ToolResult = { content: { type: string; text: string }[]; isError?: boolean };

async function call(client: Client, name: string, args: Record<string, unknown>) {
  const res = (await client.callTool({ name, arguments: args })) as ToolResult;
  return { isError: res.isError === true, text: res.content[0].text };
}

function queued(lensDb: LensDb, key = IP, type: Finding['entity_type'] = 'source_ip') {
  const trigger = type === 'client' ? 'new_client' : 'new_source_ip';
  const finding = upsertFinding(lensDb, applyTrigger(null, trigger, FIRST_SEEN, type, key));
  const request = queueForAnalysis(lensDb, finding, FIRST_SEEN);
  return { finding, request };
}

const close = { verdict: 'close', risk_level: 'low', summary: 'benign', reasoning: 'all blocked' };

describe('MCP analysis tools', () => {
  it('get_pending_analyses → get_analysis_context → submit_analysis closes the finding', async () => {
    const lensDb = openLensDb(':memory:');
    const sinkDb = seededSinkDb([
      { received_at: RECENT, category: 'ips_alert', signature: 'S', source_ip: IP, action: 'blocked' },
    ]);
    const { finding, request } = queued(lensDb);
    const client = await connectedClient(lensDb, sinkDb);

    const pending = await call(client, 'get_pending_analyses', {});
    const rows = JSON.parse(pending.text);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: request.id, entity_key: IP });
    expect(rows[0]).not.toHaveProperty('context');

    const ctx = await call(client, 'get_analysis_context', { id: request.id });
    expect(ctx.isError).toBe(false);
    const bundle = JSON.parse(ctx.text);
    expect(bundle.finding.id).toBe(finding.id);
    expect(bundle.since_last_decision).toMatchObject({ total: 1, unblocked_ips_alerts: 0 });

    const submitted = await call(client, 'submit_analysis', { id: request.id, ...close });
    expect(submitted.isError).toBe(false);
    const submittedBody = JSON.parse(submitted.text);
    expect(submittedBody.finding).toMatchObject({ status: 'closed', closed_by: 'ai' });
    expect(submittedBody.request).toMatchObject({ id: request.id, status: 'answered', verdict: 'close' });
    expect(submittedBody.request).not.toHaveProperty('context');
    expect(getFindingById(lensDb, finding.id as number)).toMatchObject({
      status: 'closed',
      closed_by: 'ai',
      closed_reason: 'benign',
    });

    const after = await call(client, 'get_pending_analyses', {});
    expect(JSON.parse(after.text)).toEqual([]);
  });

  it('get_analysis_context stores the bundle it returned on the pending request', async () => {
    const lensDb = openLensDb(':memory:');
    const { request } = queued(lensDb);
    const client = await connectedClient(lensDb, null);
    const ctx = await call(client, 'get_analysis_context', { id: request.id });
    const stored = getAnalysisRequest(lensDb, request.id);
    expect(JSON.parse(stored?.context ?? '{}')).toEqual(JSON.parse(ctx.text));
    expect(JSON.parse(ctx.text).since_last_decision).toBeNull();
  });

  it('get_analysis_context reports an unknown request as an error', async () => {
    const client = await connectedClient(openLensDb(':memory:'), null);
    const res = await call(client, 'get_analysis_context', { id: 42 });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/42 not found/);
  });

  it('submit_analysis returns isError for a close with unblocked alerts', async () => {
    const lensDb = openLensDb(':memory:');
    const sinkDb = seededSinkDb([
      { received_at: RECENT, category: 'ips_alert', signature: 'S', source_ip: IP, action: 'allowed' },
      { received_at: RECENT, category: 'ips_alert', signature: 'S', source_ip: IP, action: null },
    ]);
    const { finding, request } = queued(lensDb);
    const client = await connectedClient(lensDb, sinkDb);
    const res = await call(client, 'submit_analysis', { id: request.id, ...close });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/2 IPS alert\(s\)/);
    expect(getFindingById(lensDb, finding.id as number)?.status).toBe('triaging');
    expect(getAnalysisRequest(lensDb, request.id)?.status).toBe('pending');

    const attention = await call(client, 'submit_analysis', {
      id: request.id,
      ...close,
      verdict: 'attention',
      risk_level: 'high',
      recommended_action: 'check the host',
    });
    expect(attention.isError).toBe(false);
    expect(getFindingById(lensDb, finding.id as number)?.status).toBe('attention');
  });

  it('submit_analysis close without a sink is rejected as sink unavailable', async () => {
    const lensDb = openLensDb(':memory:');
    const { request } = queued(lensDb);
    const client = await connectedClient(lensDb, null);
    const res = await call(client, 'submit_analysis', { id: request.id, ...close });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/sink DB unavailable/);
  });

  it('submit_analysis close on a client finding against an old sink is rejected as sink unavailable', async () => {
    const conn = new DatabaseSync(':memory:');
    conn.exec(
      `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
       category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
       dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
       signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER)`
    );
    const lensDb = openLensDb(':memory:');
    const { request } = queued(lensDb, MAC, 'client');
    const client = await connectedClient(lensDb, { conn });
    const res = await call(client, 'submit_analysis', { id: request.id, ...close });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/sink DB unavailable/);
  });

  it('submit_analysis on an unknown request reports not found', async () => {
    const client = await connectedClient(openLensDb(':memory:'), null);
    const res = await call(client, 'submit_analysis', { id: 7, ...close });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/7 not found/);
  });

  it('get_pending_analyses honours limit', async () => {
    const lensDb = openLensDb(':memory:');
    queued(lensDb, '198.51.100.1');
    queued(lensDb, '198.51.100.2');
    queued(lensDb, '198.51.100.3');
    const client = await connectedClient(lensDb, null);
    const res = await call(client, 'get_pending_analyses', { limit: 2 });
    expect(JSON.parse(res.text)).toHaveLength(2);
    const bad = (await client.callTool({
      name: 'get_pending_analyses',
      arguments: { limit: 0 },
    })) as ToolResult;
    expect(bad.isError).toBe(true);
  });
});

describe('submit_analysis citations', () => {
  const T = '2026-01-01T00:00:00.000Z';

  async function setup(action: string) {
    const lensDb = openLensDb(':memory:');
    const sinkDb = seededSinkDb([
      { received_at: RECENT, category: 'ips_alert', signature: 'S', source_ip: IP, action },
    ]);
    const { finding, request } = queued(lensDb);
    const client = await connectedClient(lensDb, sinkDb);
    const submit = (cited: number[]) =>
      call(client, 'submit_analysis', { id: request.id, ...close, cited_entries: cited });
    const status = () => getFindingById(lensDb, finding.id as number)?.status;
    const requestStatus = () => getAnalysisRequest(lensDb, request.id)?.status;
    return { lensDb, submit, status, requestStatus };
  }

  const operatorEntry = (lensDb: LensDb) =>
    humanChange(lensDb, { op: 'add', title: 'Mine', body: 'my entry' }, T).entry;

  function defaultEntry(lensDb: LensDb) {
    seedPlaybookDefaults(lensDb, PLAYBOOK_DEFAULTS.slice(0, 1), T);
    return listEntries(lensDb)[0];
  }

  it('a close citing an active entry is accepted despite unblocked alerts', async () => {
    const { lensDb, submit, status } = await setup('allowed');
    const res = await submit([operatorEntry(lensDb).id]);
    expect(res.isError).toBe(false);
    expect(status()).toBe('closed');
  });

  it('citing a retired entry is rejected and the request stays pending', async () => {
    const { lensDb, submit, status, requestStatus } = await setup('allowed');
    const { id } = operatorEntry(lensDb);
    humanChange(lensDb, { op: 'retire', entry_id: id }, T);
    const res = await submit([id]);
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/unknown or inactive/);
    expect(requestStatus()).toBe('pending');
    expect(status()).toBe('triaging');
  });

  it('a close citing only a shipped default is rejected when alerts are unblocked', async () => {
    const { lensDb, submit, status, requestStatus } = await setup('allowed');
    const res = await submit([defaultEntry(lensDb).id]);
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/shipped default can't by itself justify/);
    expect(res.text).toMatch(/operator-written entry or choose attention/);
    expect(requestStatus()).toBe('pending');
    expect(status()).toBe('triaging');
  });

  it('a close citing an operator-edited default is accepted when alerts are unblocked', async () => {
    const { lensDb, submit, status } = await setup('allowed');
    const { id } = defaultEntry(lensDb);
    humanChange(lensDb, { op: 'edit', entry_id: id, title: 'Mine', body: 'my text' }, T);
    const res = await submit([id]);
    expect(res.isError).toBe(false);
    expect(status()).toBe('closed');
  });

  it('a close citing a default is accepted when everything was blocked', async () => {
    const { lensDb, submit, status } = await setup('blocked');
    const res = await submit([defaultEntry(lensDb).id]);
    expect(res.isError).toBe(false);
    expect(status()).toBe('closed');
  });
});
