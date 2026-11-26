import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import {
  applyAiVerdict,
  closeByRule,
  humanClose,
  humanReopen,
  queueForAnalysis,
  recheckStillClosed,
} from '../../src/analysis/pipeline.js';
import { addHistory, type HistoryKind } from '../../src/db/findingHistoryStore.js';
import { updateFindingState, upsertFinding } from '../../src/db/findingsStore.js';
import { type LensDb, openLensDb } from '../../src/db/lensDb.js';
import { humanChange, listEntries, listProposals } from '../../src/db/playbookStore.js';
import { createMcpServer } from '../../src/mcp/server.js';

async function connect(lensDb: LensDb) {
  const server = createMcpServer(
    {
      lensDb,
      eventsDb: null,
      unifiMcp: { resolveClient: async () => null, getFirewallSummary: async () => null },
      homelabServices: {},
    },
    { trustedAdminNames: [] }
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.1.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

type ToolResult = { content: { type: string; text: string }[]; isError?: boolean };

async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const res = (await client.callTool({ name, arguments: args })) as ToolResult;
  return { isError: res.isError === true, text: res.content[0].text };
}

async function json(client: Client, name: string, args: Record<string, unknown> = {}) {
  const res = await call(client, name, args);
  if (res.isError) throw new Error(res.text);
  return JSON.parse(res.text);
}

function historyRow(
  db: LensDb,
  key: string,
  kind: HistoryKind,
  status: 'closed' | 'attention',
  at: string
) {
  const finding = upsertFinding(
    db,
    applyTrigger(null, 'new_source_ip', at, 'source_ip', key)
  );
  updateFindingState(db, finding.id as number, { status });
  return addHistory(db, {
    finding_id: finding.id as number,
    at,
    kind,
    actor: kind.startsWith('human') ? 'human' : 'ai',
    summary: kind,
    note: 'note',
  });
}

function seedFeedback(db: LensDb) {
  // Inserted newest first, so ordering can't come from insertion order.
  const reopened = historyRow(db, '198.51.100.2', 'human_reopened', 'attention', 't2');
  const handled = historyRow(db, '198.51.100.1', 'human_closed_handled', 'closed', 't1');
  const ai = historyRow(db, '198.51.100.3', 'ai_closed', 'closed', 't0');
  return { handled, reopened, ai };
}

const proposal = {
  op: 'add',
  title: 'Host A VPN',
  body: 'VPN flows from 192.0.2.10 are benign',
  rationale: 'operator marked it Not a concern',
  evidence: { finding_ids: [1], history_ids: [2] },
};

describe('feedback tools', () => {
  it('get_feedback returns unconsidered human rows across statuses', async () => {
    const db = openLensDb(':memory:');
    const { handled, reopened } = seedFeedback(db);
    const rows = await json(await connect(db), 'get_feedback');
    expect(rows.map((r: { id: number }) => r.id)).toEqual([handled.id, reopened.id]);
    expect(rows[0]).toMatchObject({
      kind: 'human_closed_handled',
      note: 'note',
      finding_id: handled.finding_id,
      entity_type: 'source_ip',
      entity_key: '198.51.100.1',
      status: 'closed',
    });
    expect(rows[1]).toMatchObject({ entity_key: '198.51.100.2', status: 'attention' });
  });

  it('get_feedback includes not-a-concern rows and honours limit', async () => {
    const db = openLensDb(':memory:');
    historyRow(db, '198.51.100.4', 'human_closed_not_concern', 'closed', 't1');
    historyRow(db, '198.51.100.5', 'human_reopened', 'attention', 't2');
    const client = await connect(db);
    const rows = await json(client, 'get_feedback', { limit: 1 });
    expect(rows).toHaveLength(1);
    expect(rows[0].kind).toBe('human_closed_not_concern');
    for (const limit of [0, 101]) {
      expect((await call(client, 'get_feedback', { limit })).isError).toBe(true);
    }
  });

  it('mark_feedback_considered marks only human feedback rows and ignores unknown ids', async () => {
    const db = openLensDb(':memory:');
    const { handled, reopened, ai } = seedFeedback(db);
    const client = await connect(db);
    expect(await json(client, 'mark_feedback_considered', { ids: [handled.id, ai.id, 99999] })).toEqual(
      { marked: 1 }
    );
    const rows = await json(client, 'get_feedback');
    expect(rows.map((r: { id: number }) => r.id)).toEqual([reopened.id]);
    const aiRow = db.conn
      .prepare('SELECT feedback_considered_at FROM finding_history WHERE id = ?')
      .get(ai.id) as { feedback_considered_at: string | null };
    expect(aiRow.feedback_considered_at).toBeNull();
  });

  it('a marked row never comes back', async () => {
    const db = openLensDb(':memory:');
    const { handled } = seedFeedback(db);
    const client = await connect(db);
    await json(client, 'mark_feedback_considered', { ids: [handled.id] });
    expect(await json(client, 'mark_feedback_considered', { ids: [handled.id] })).toEqual({
      marked: 0,
    });
    expect(await json(client, 'mark_feedback_considered', { ids: [] })).toEqual({ marked: 0 });
    const rows = await json(client, 'get_feedback');
    expect(rows.map((r: { id: number }) => r.id)).not.toContain(handled.id);
  });
});

describe('get_feedback: what a reopen undid', () => {
  const match = {
    rule: 'reputation_blocklist' as const,
    verdict: { recommendation: 'blocked blocklist hit', riskLevel: 'low' as const },
  };

  const finding = (db: LensDb, key: string) =>
    upsertFinding(db, applyTrigger(null, 'new_source_ip', 't0', 'source_ip', key));

  type Row = { kind: string; finding_id: number; reopened_from: unknown };
  const feedback = async (db: LensDb): Promise<Row[]> =>
    json(await connect(db), 'get_feedback');

  it('names the rule behind a reopened rule close', async () => {
    const db = openLensDb(':memory:');
    const f = finding(db, '198.51.100.1');
    closeByRule(db, f, match, 't1');
    humanReopen(db, f.id as number, 'wrong', 't2');
    const rows = await feedback(db);
    expect(rows).toHaveLength(1);
    expect(rows[0].reopened_from).toEqual({
      kind: 'rule_closed',
      summary: 'Closed by rule reputation_blocklist',
    });
  });

  it('reports the latest close before the reopen, such as a rule recheck', async () => {
    const db = openLensDb(':memory:');
    const f = finding(db, '198.51.100.1');
    const closed = closeByRule(db, f, match, 't1');
    recheckStillClosed(db, closed, match, 't2');
    humanReopen(db, f.id as number, 'wrong', 't3');
    expect((await feedback(db))[0].reopened_from).toEqual({
      kind: 'recheck_rule_still_closed',
      summary: 'Recheck: rule reputation_blocklist still closes this finding',
    });
  });

  it('shows a reopened AI close with its summary', async () => {
    const db = openLensDb(':memory:');
    const f = finding(db, '198.51.100.1');
    const request = queueForAnalysis(db, f, 't1');
    applyAiVerdict(
      db,
      request.id,
      { verdict: 'close', risk_level: 'low', summary: 'benign scanner', reasoning: 'r' },
      {
        unblockedIpsAlertsSinceDecision: 0,
        activeEntryIds: new Set<number>(),
        operatorBackedEntryIds: new Set<number>(),
      },
      't2'
    );
    humanReopen(db, f.id as number, 'wrong', 't3');
    expect((await feedback(db))[0].reopened_from).toEqual({
      kind: 'ai_closed',
      summary: 'benign scanner',
    });
  });

  it('uses only earlier closes of the same finding, and only for reopen rows', async () => {
    const db = openLensDb(':memory:');
    const other = finding(db, '198.51.100.2');
    closeByRule(db, other, match, 't1');
    // A reopen with no close on record (e.g. closed before history existed).
    const bare = historyRow(db, '198.51.100.1', 'human_reopened', 'attention', 't2');
    humanClose(db, bare.finding_id, 'handled', null, 't3');
    humanReopen(db, bare.finding_id, 'again', 't4');
    const rows = await feedback(db);
    expect(rows.map((r) => [r.kind, r.reopened_from])).toEqual([
      ['human_reopened', null],
      ['human_closed_handled', null],
      ['human_reopened', { kind: 'human_closed_handled', summary: 'Closed as handled' }],
    ]);
  });
});

describe('proposal tools', () => {
  it('propose_playbook_change creates a pending ai proposal and no entry', async () => {
    const db = openLensDb(':memory:');
    const client = await connect(db);
    const created = await json(client, 'propose_playbook_change', proposal);
    expect(created).toMatchObject({ ...proposal, status: 'pending', proposed_by: 'ai' });
    const pending = await json(client, 'list_playbook_proposals', { status: 'pending' });
    expect(pending).toEqual([created]);
    expect(await json(client, 'list_playbook_proposals', { status: 'rejected' })).toEqual([]);
    expect(await json(client, 'list_playbook_proposals')).toEqual([created]);
    expect(listEntries(db)).toEqual([]);
  });

  it('propose_playbook_change ignores attempts to set status or proposed_by', async () => {
    const db = openLensDb(':memory:');
    const client = await connect(db);
    await call(client, 'propose_playbook_change', {
      ...proposal,
      status: 'accepted',
      proposed_by: 'human',
    });
    expect(listProposals(db)).toHaveLength(1);
    expect(listProposals(db)[0]).toMatchObject({ status: 'pending', proposed_by: 'ai' });
    expect(listEntries(db)).toEqual([]);
  });

  it('proposes an edit of an existing entry without changing it', async () => {
    const db = openLensDb(':memory:');
    const { entry } = humanChange(db, { op: 'add', title: 'T', body: 'B' }, 't0');
    const created = await json(await connect(db), 'propose_playbook_change', {
      ...proposal,
      op: 'edit',
      entry_id: entry.id,
    });
    expect(created).toMatchObject({ op: 'edit', entry_id: entry.id, status: 'pending' });
    expect(listEntries(db)).toEqual([entry]);
  });

  it('propose edit of a missing entry is a tool error', async () => {
    const db = openLensDb(':memory:');
    const res = await call(await connect(db), 'propose_playbook_change', {
      ...proposal,
      op: 'edit',
      entry_id: 999,
    });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/entry_id of an existing entry/);
    expect(listProposals(db)).toEqual([]);
  });

  it("a retire with blank title and body stores the entry's text", async () => {
    const db = openLensDb(':memory:');
    const { entry } = humanChange(db, { op: 'add', title: 'T', body: 'B' }, 't0');
    const created = await json(await connect(db), 'propose_playbook_change', {
      ...proposal,
      op: 'retire',
      entry_id: entry.id,
      title: '',
      body: '',
    });
    expect(created).toMatchObject({ op: 'retire', title: 'T', body: 'B', status: 'pending' });
    expect(listEntries(db)).toEqual([entry]);
  });

  it('a blank rationale is a tool error', async () => {
    const db = openLensDb(':memory:');
    const res = await call(await connect(db), 'propose_playbook_change', {
      ...proposal,
      rationale: '  ',
    });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/rationale must not be blank/);
    expect(listProposals(db)).toEqual([]);
  });
});

describe('import_knowledge prompt', () => {
  it('names the registry, propose_playbook_change and get_playbook', async () => {
    const client = await connect(openLensDb(':memory:'));
    expect((await client.listPrompts()).prompts.map((p) => p.name)).toContain('import_knowledge');
    const res = await client.getPrompt({ name: 'import_knowledge' });
    expect(res.messages).toHaveLength(1);
    expect(res.messages[0].role).toBe('user');
    const text = (res.messages[0].content as { text: string }).text;
    expect(text).toContain('homelab-services.json');
    expect(text).toContain('`wanExposed`');
    expect(text).toContain('`propose_playbook_change`');
    expect(text).toContain('`list_playbook_proposals`');
    expect(text.indexOf('`get_playbook`')).toBeGreaterThanOrEqual(0);
    expect(text.indexOf('`get_playbook`')).toBeLessThan(text.indexOf('`propose_playbook_change`'));
  });
});
