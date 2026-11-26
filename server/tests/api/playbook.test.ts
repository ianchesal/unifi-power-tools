import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { createPlaybookRouter } from '../../src/api/playbook.js';
import { updateFindingState, upsertFinding } from '../../src/db/findingsStore.js';
import { type LensDb, openLensDb } from '../../src/db/lensDb.js';
import {
  createProposal,
  humanChange,
  listEntries,
  listProposals,
  type ProposalOp,
} from '../../src/db/playbookStore.js';
import type { HomelabRegistry } from '../../src/enrichment/homelabServices.js';
import { PLAYBOOK_DEFAULTS } from '../../src/mcp/playbook/defaults.js';
import { seedPlaybookDefaults } from '../../src/mcp/playbook/seed.js';

const T0 = '2026-01-01T00:00:00.000Z';
const T1 = '2026-01-02T00:00:00.000Z';

const registry: HomelabRegistry = {
  '192.0.2.10': { label: 'example-host', services: [{ port: 8080, name: 'example' }] },
};

function setup(homelab: HomelabRegistry = {}) {
  const db = openLensDb(':memory:');
  const app = express();
  app.use(express.json());
  app.use('/api/playbook', createPlaybookRouter(db, homelab));
  return { db, api: request(app) };
}

const seedEntry = (db: LensDb, title = 'Seed') =>
  humanChange(db, { op: 'add', title, body: `${title} body` }, T0).entry;

function pendingProposal(
  db: LensDb,
  op: ProposalOp = 'add',
  entryId?: number,
  findingIds: number[] = []
) {
  return createProposal(
    db,
    {
      op,
      entry_id: entryId,
      title: 'Proposed',
      body: 'proposed body',
      rationale: 'why',
      evidence: { finding_ids: findingIds, history_ids: [] },
      proposed_by: 'ai',
    },
    T1
  );
}

describe('GET /api/playbook', () => {
  it('lists active entries then retired ones, with the registry passed in', async () => {
    const { db, api } = setup(registry);
    const first = seedEntry(db, 'First');
    const second = seedEntry(db, 'Second');
    humanChange(db, { op: 'retire', entry_id: first.id }, T1);

    const res = await api.get('/api/playbook');
    expect(res.status).toBe(200);
    expect(res.body.entries.map((e: { id: number; status: string }) => [e.id, e.status])).toEqual([
      [second.id, 'active'],
      [first.id, 'retired'],
    ]);
    expect(res.body.entries[0]).toMatchObject({ ...second, is_default: false });
    expect(res.body.registry).toEqual(registry);
  });

  it('marks entries that are still shipped default text', async () => {
    const { db, api } = setup();
    seedPlaybookDefaults(db, PLAYBOOK_DEFAULTS.slice(0, 2), T0);
    const [kept, edited] = listEntries(db);
    humanChange(db, { op: 'edit', entry_id: edited.id, title: 'Mine', body: 'mine' }, T1);

    const res = await api.get('/api/playbook');
    expect(
      res.body.entries.map((e: { id: number; is_default: boolean }) => [e.id, e.is_default])
    ).toEqual([
      [kept.id, true],
      [edited.id, false],
    ]);
  });
});

describe('GET /api/playbook/proposals', () => {
  it('resolves evidence findings, dropping missing ids, and the current entry', async () => {
    const { db, api } = setup();
    const f = upsertFinding(
      db,
      applyTrigger(null, 'new_source_ip', T0, 'source_ip', '198.51.100.1')
    );
    updateFindingState(db, f.id as number, { status: 'attention' });
    const entry = seedEntry(db);
    const edit = pendingProposal(db, 'edit', entry.id, [999, f.id as number]);
    const add = pendingProposal(db);
    const retire = pendingProposal(db, 'retire', entry.id);

    const res = await api.get('/api/playbook/proposals?status=pending');
    expect(res.status).toBe(200);
    const byId = new Map(res.body.map((p: { id: number }) => [p.id, p]));
    expect(res.body).toHaveLength(3);
    expect(byId.get(edit.id)).toEqual({
      ...edit,
      evidence_findings: [
        { id: f.id, entity_type: 'source_ip', entity_key: '198.51.100.1', status: 'attention' },
      ],
      missing_evidence_count: 1,
      current: { title: 'Seed', body: 'Seed body', status: 'active' },
    });
    expect(byId.get(add.id)).toMatchObject({
      evidence_findings: [],
      missing_evidence_count: 0,
      current: null,
    });
    expect(byId.get(retire.id)).toMatchObject({
      current: { title: 'Seed', body: 'Seed body', status: 'active' },
    });
  });

  it('returns every proposal without a status, and null current for a vanished entry', async () => {
    const { db, api } = setup();
    const entry = seedEntry(db);
    const edit = pendingProposal(db, 'edit', entry.id);
    db.conn.prepare('DELETE FROM playbook_entries WHERE id = ?').run(entry.id);

    const res = await api.get('/api/playbook/proposals');
    expect(res.body).toHaveLength(2);
    expect(res.body[0]).toMatchObject({ id: edit.id, current: null });
    expect(res.body[1].status).toBe('accepted');
  });

  it('rejects an unknown status', async () => {
    const { api } = setup();
    const res = await api.get('/api/playbook/proposals?status=nope');
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/status must be one of/);
  });
});

describe('POST /api/playbook/proposals', () => {
  it('records and applies a human add', async () => {
    const { db, api } = setup();
    const res = await api.post('/api/playbook/proposals').send({ title: 'Mine', body: 'my body' });
    expect(res.status).toBe(201);
    expect(res.body.proposal).toMatchObject({
      op: 'add',
      proposed_by: 'human',
      status: 'accepted',
    });
    expect(res.body.entry).toMatchObject({ title: 'Mine', body: 'my body', status: 'active' });
    expect(listEntries(db)).toEqual([res.body.entry]);
  });

  it('rejects a missing or blank title or body', async () => {
    const { db, api } = setup();
    for (const body of [{}, { title: 'T' }, { title: ' ', body: 'B' }, { title: 'T', body: 1 }]) {
      const res = await api.post('/api/playbook/proposals').send(body);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('title and body are required');
    }
    expect(listProposals(db)).toEqual([]);
  });
});

describe('POST /api/playbook/proposals/:id/accept', () => {
  it('applies the proposal', async () => {
    const { db, api } = setup();
    const p = pendingProposal(db);
    const res = await api.post(`/api/playbook/proposals/${p.id}/accept`).send({});
    expect(res.status).toBe(200);
    expect(res.body.proposal).toMatchObject({ id: p.id, status: 'accepted' });
    expect(res.body.entry).toMatchObject({ title: 'Proposed', body: 'proposed body' });
  });

  it('applies edited text', async () => {
    const { db, api } = setup();
    const p = pendingProposal(db);
    const res = await api
      .post(`/api/playbook/proposals/${p.id}/accept`)
      .send({ edited_title: 'Edited', edited_body: 'edited body' });
    expect(res.status).toBe(200);
    expect(res.body.entry).toMatchObject({ title: 'Edited', body: 'edited body' });
    expect(res.body.proposal.body).toBe('edited body');
  });

  it('is a 409 the second time', async () => {
    const { db, api } = setup();
    const p = pendingProposal(db);
    await api.post(`/api/playbook/proposals/${p.id}/accept`).send({});
    const res = await api.post(`/api/playbook/proposals/${p.id}/accept`).send({});
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/already accepted/);
    expect(listEntries(db)).toHaveLength(1);
  });

  it('is a 400 for blank edited text, leaving the proposal pending', async () => {
    const { db, api } = setup();
    const p = pendingProposal(db);
    const res = await api
      .post(`/api/playbook/proposals/${p.id}/accept`)
      .send({ edited_body: '  ' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBeTruthy();
    expect(listProposals(db)[0].status).toBe('pending');
  });
});

describe('POST /api/playbook/proposals/:id/reject', () => {
  it('rejects with the note', async () => {
    const { db, api } = setup();
    const p = pendingProposal(db);
    const res = await api.post(`/api/playbook/proposals/${p.id}/reject`).send({ note: 'broad' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: p.id, status: 'rejected', decision_note: 'broad' });
    expect(listEntries(db)).toEqual([]);
  });

  it('stores no note when none or a blank one is given', async () => {
    const { db, api } = setup();
    for (const body of [{}, { note: '  ' }]) {
      const p = pendingProposal(db);
      const res = await api.post(`/api/playbook/proposals/${p.id}/reject`).send(body);
      expect(res.body.decision_note).toBeNull();
    }
  });

  it('is a 409 for a decided proposal', async () => {
    const { db, api } = setup();
    const p = pendingProposal(db);
    await api.post(`/api/playbook/proposals/${p.id}/reject`).send({});
    const res = await api.post(`/api/playbook/proposals/${p.id}/reject`).send({});
    expect(res.status).toBe(409);
  });
});

describe('PUT /api/playbook/entries/:id', () => {
  it('records and applies a human edit', async () => {
    const { db, api } = setup();
    const entry = seedEntry(db);
    const res = await api
      .put(`/api/playbook/entries/${entry.id}`)
      .send({ title: 'New', body: 'new body' });
    expect(res.status).toBe(200);
    expect(res.body.entry).toMatchObject({ id: entry.id, title: 'New', body: 'new body' });
    expect(res.body.proposal).toMatchObject({ op: 'edit', proposed_by: 'human' });
  });

  it('is a 400 on a missing entry', async () => {
    const { db, api } = setup();
    const res = await api.put('/api/playbook/entries/999').send({ title: 'T', body: 'B' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/existing entry/);
    expect(listProposals(db)).toEqual([]);
  });

  it('is a 400 without a title and body', async () => {
    const { db, api } = setup();
    const entry = seedEntry(db);
    const res = await api.put(`/api/playbook/entries/${entry.id}`).send({ title: 'only' });
    expect(res.status).toBe(400);
    expect(listEntries(db)).toEqual([entry]);
  });
});

describe('POST /api/playbook/entries/:id/retire', () => {
  it('retires with a default rationale', async () => {
    const { db, api } = setup();
    const entry = seedEntry(db);
    const res = await api.post(`/api/playbook/entries/${entry.id}/retire`).send({});
    expect(res.status).toBe(200);
    expect(res.body.entry).toMatchObject({ id: entry.id, status: 'retired' });
    expect(res.body.proposal).toMatchObject({
      op: 'retire',
      proposed_by: 'human',
      rationale: 'Retired from the dashboard',
    });
  });

  it('records the note as the rationale, ignoring a blank one', async () => {
    const { db, api } = setup();
    const a = seedEntry(db, 'A');
    const b = seedEntry(db, 'B');
    const noted = await api.post(`/api/playbook/entries/${a.id}/retire`).send({ note: 'moved' });
    expect(noted.body.proposal.rationale).toBe('moved');
    const blank = await api.post(`/api/playbook/entries/${b.id}/retire`).send({ note: ' ' });
    expect(blank.body.proposal.rationale).toBe('Retired from the dashboard');
  });

  it('is a 400 on a missing entry', async () => {
    const { api } = setup();
    expect((await api.post('/api/playbook/entries/999/retire').send({})).status).toBe(400);
  });
});

describe('playbook API errors', () => {
  it('maps an unknown proposal to 404', async () => {
    const { api } = setup();
    for (const action of ['accept', 'reject']) {
      const res = await api.post(`/api/playbook/proposals/999/${action}`).send({});
      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/999 not found/);
    }
  });

  it('rejects a non-integer id', async () => {
    const { api } = setup();
    for (const id of ['abc', '1.5', '-1', '1e0']) {
      const responses = [
        await api.post(`/api/playbook/proposals/${id}/accept`).send({}),
        await api.post(`/api/playbook/proposals/${id}/reject`).send({}),
        await api.put(`/api/playbook/entries/${id}`).send({ title: 'T', body: 'B' }),
        await api.post(`/api/playbook/entries/${id}/retire`).send({}),
      ];
      for (const res of responses) {
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('id must be an integer');
      }
    }
  });

  // A cross-site page can POST without a preflight only if it sends no JSON
  // body, so every write requires one.
  it('rejects writes without a JSON body, changing nothing', async () => {
    const { db, api } = setup();
    const entry = seedEntry(db);
    const p = pendingProposal(db);
    const urls = [
      `/api/playbook/proposals/${p.id}/accept`,
      `/api/playbook/proposals/${p.id}/reject`,
      `/api/playbook/entries/${entry.id}/retire`,
    ];
    for (const url of urls) {
      expect((await api.post(url)).status).toBe(400);
      const text = await api.post(url).set('Content-Type', 'text/plain').send('{}');
      expect(text.status).toBe(400);
    }
    expect(listProposals(db, { status: 'pending' }).map((r) => r.id)).toEqual([p.id]);
    expect(listEntries(db)).toEqual([entry]);
  });
});

describe('minor fixes', () => {
  it('rejects a misspelled accept field instead of applying the unedited text', async () => {
    const { db, api } = setup();
    const p = pendingProposal(db);
    const res = await api.post(`/api/playbook/proposals/${p.id}/accept`).send({ edited_boby: 'x' });
    expect(res.status).toBe(400);
    expect(listProposals(db, { status: 'pending' })).toHaveLength(1);
  });
});
