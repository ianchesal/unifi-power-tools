import { describe, expect, it } from 'vitest';
import { openLensDb } from '../../src/db/lensDb.js';
import {
  acceptProposal,
  activeEntryIds,
  createProposal,
  humanChange,
  listEntries,
  listProposals,
  operatorBackedEntryIds,
  ProposalError,
  type ProposedBy,
  rejectProposal,
} from '../../src/db/playbookStore.js';

const T0 = '2026-01-01T00:00:00.000Z';
const T1 = '2026-01-02T00:00:00.000Z';
const T2 = '2026-01-03T00:00:00.000Z';

type Db = ReturnType<typeof openLensDb>;

const addInput = (proposed_by: ProposedBy = 'ai') => ({
  op: 'add' as const,
  title: 'Host A VPN',
  body: 'Hits on the VPN flows from host A are false positives',
  rationale: 'seen twice',
  evidence: { finding_ids: [1, 2], history_ids: [3] },
  proposed_by,
});

const seedEntry = (db: Db) =>
  humanChange(db, { op: 'add', title: 'Seed', body: 'seed body' }, T0).entry;

function errorCode(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (err) {
    if (err instanceof ProposalError) return err.code;
    throw err;
  }
  return undefined;
}

describe('playbookStore', () => {
  it('migration 5 creates the three tables', () => {
    const db = openLensDb(':memory:');
    const names = (
      db.conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as {
        name: string;
      }[]
    ).map((r) => r.name);
    expect(names).toEqual(
      expect.arrayContaining([
        'playbook_entries',
        'playbook_proposals',
        'playbook_defaults_seen',
      ])
    );
    db.close();
  });

  it('an ai proposal is pending and creates no entry', () => {
    const db = openLensDb(':memory:');
    const proposal = createProposal(db, addInput(), T0);
    expect(proposal).toMatchObject({
      op: 'add',
      entry_id: null,
      status: 'pending',
      proposed_by: 'ai',
      created_at: T0,
      decided_at: null,
      decision_note: null,
    });
    expect(listEntries(db)).toEqual([]);
    db.close();
  });

  it('accepting an add inserts an active entry linked to the proposal', () => {
    const db = openLensDb(':memory:');
    const created = createProposal(db, addInput(), T0);
    const { proposal, entry } = acceptProposal(db, created.id, null, T1);
    expect(entry).toMatchObject({
      title: created.title,
      body: created.body,
      status: 'active',
      source_proposal_id: created.id,
      default_key: null,
      created_at: T1,
      updated_at: T1,
    });
    expect(proposal).toMatchObject({ status: 'accepted', decided_at: T1 });
    expect(activeEntryIds(db).has(entry.id)).toBe(true);
    expect(listEntries(db)).toEqual([entry]);
    db.close();
  });

  it('accept with edits applies and records the edited text', () => {
    const db = openLensDb(':memory:');
    const created = createProposal(db, addInput(), T0);
    const { proposal, entry } = acceptProposal(db, created.id, { body: 'edited' }, T1);
    expect(entry.body).toBe('edited');
    expect(entry.title).toBe(created.title);
    expect(proposal.body).toBe('edited');
    expect(listProposals(db)[0].body).toBe('edited');
    db.close();
  });

  it('accept with blank edited text is invalid and leaves the proposal pending', () => {
    const db = openLensDb(':memory:');
    const created = createProposal(db, addInput(), T0);
    expect(errorCode(() => acceptProposal(db, created.id, { title: '  ' }, T1))).toBe('invalid');
    expect(listProposals(db)[0].status).toBe('pending');
    expect(listEntries(db)).toEqual([]);
    db.close();
  });

  it('accepting an edit updates the entry text and keeps its source', () => {
    const db = openLensDb(':memory:');
    const seeded = seedEntry(db);
    const created = createProposal(
      db,
      { ...addInput(), op: 'edit', entry_id: seeded.id, title: 'New', body: 'new body' },
      T1
    );
    const { entry } = acceptProposal(db, created.id, null, T2);
    expect(entry).toEqual({ ...seeded, title: 'New', body: 'new body', updated_at: T2 });
    db.close();
  });

  it('edit of a retired entry reactivates it', () => {
    const db = openLensDb(':memory:');
    const seeded = seedEntry(db);
    humanChange(db, { op: 'retire', entry_id: seeded.id }, T1);
    const created = createProposal(db, { ...addInput(), op: 'edit', entry_id: seeded.id }, T1);
    const { entry } = acceptProposal(db, created.id, null, T2);
    expect(entry.status).toBe('active');
    db.close();
  });

  it('accepting a decided proposal is a conflict', () => {
    const db = openLensDb(':memory:');
    const created = createProposal(db, addInput(), T0);
    acceptProposal(db, created.id, null, T1);
    expect(errorCode(() => acceptProposal(db, created.id, null, T2))).toBe('conflict');
    expect(errorCode(() => rejectProposal(db, created.id, null, T2))).toBe('conflict');
    expect(listEntries(db)).toHaveLength(1);
    expect(listProposals(db)[0]).toMatchObject({ status: 'accepted', decided_at: T1 });
    db.close();
  });

  it('rejecting records the note and creates no entry', () => {
    const db = openLensDb(':memory:');
    const created = createProposal(db, addInput(), T0);
    const rejected = rejectProposal(db, created.id, 'too broad', T1);
    expect(rejected).toMatchObject({
      status: 'rejected',
      decided_at: T1,
      decision_note: 'too broad',
    });
    expect(listEntries(db)).toEqual([]);
    expect(errorCode(() => acceptProposal(db, created.id, null, T2))).toBe('conflict');
    db.close();
  });

  it('accepting or rejecting an unknown proposal is not_found', () => {
    const db = openLensDb(':memory:');
    expect(errorCode(() => acceptProposal(db, 999, null, T0))).toBe('not_found');
    expect(errorCode(() => rejectProposal(db, 999, null, T0))).toBe('not_found');
    db.close();
  });

  it('edit or retire of a missing entry is invalid', () => {
    const db = openLensDb(':memory:');
    for (const op of ['edit', 'retire'] as const) {
      expect(errorCode(() => createProposal(db, { ...addInput(), op, entry_id: 999 }, T0))).toBe(
        'invalid'
      );
      expect(errorCode(() => createProposal(db, { ...addInput(), op }, T0))).toBe('invalid');
    }
    expect(listProposals(db)).toEqual([]);
    db.close();
  });

  it('accepting a proposal whose entry vanished is invalid and leaves it pending', () => {
    const db = openLensDb(':memory:');
    const seeded = seedEntry(db);
    const created = createProposal(db, { ...addInput(), op: 'retire', entry_id: seeded.id }, T1);
    db.conn.prepare('DELETE FROM playbook_entries WHERE id = ?').run(seeded.id);
    expect(errorCode(() => acceptProposal(db, created.id, null, T2))).toBe('invalid');
    expect(listProposals(db)[0]).toMatchObject({ id: created.id, status: 'pending' });
    db.close();
  });

  it('add with an entry_id is invalid', () => {
    const db = openLensDb(':memory:');
    const seeded = seedEntry(db);
    expect(errorCode(() => createProposal(db, { ...addInput(), entry_id: seeded.id }, T0))).toBe(
      'invalid'
    );
    db.close();
  });

  it('blank title is invalid', () => {
    const db = openLensDb(':memory:');
    const seeded = seedEntry(db);
    expect(errorCode(() => createProposal(db, { ...addInput(), title: '  ' }, T0))).toBe(
      'invalid'
    );
    expect(errorCode(() => createProposal(db, { ...addInput(), body: '' }, T0))).toBe('invalid');
    expect(
      errorCode(() =>
        createProposal(db, { ...addInput(), op: 'edit', entry_id: seeded.id, title: '' }, T0)
      )
    ).toBe('invalid');
    db.close();
  });

  it('humanChange records an accepted human proposal', () => {
    const db = openLensDb(':memory:');
    const { proposal, entry } = humanChange(
      db,
      { op: 'add', title: 'Mine', body: 'my body', rationale: 'because' },
      T0
    );
    expect(proposal).toMatchObject({
      op: 'add',
      proposed_by: 'human',
      status: 'accepted',
      rationale: 'because',
      evidence: { finding_ids: [], history_ids: [] },
      created_at: T0,
      decided_at: T0,
    });
    expect(entry).toMatchObject({ title: 'Mine', body: 'my body', status: 'active' });
    expect(listEntries(db)).toEqual([entry]);
    db.close();
  });

  it('humanChange retire copies the missing title and body from the entry', () => {
    const db = openLensDb(':memory:');
    const seeded = seedEntry(db);
    const { proposal, entry } = humanChange(db, { op: 'retire', entry_id: seeded.id }, T1);
    expect(proposal).toMatchObject({
      op: 'retire',
      entry_id: seeded.id,
      title: 'Seed',
      body: 'seed body',
    });
    expect(entry.status).toBe('retired');
    db.close();
  });

  it('humanChange add or edit without text is invalid and records nothing', () => {
    const db = openLensDb(':memory:');
    const seeded = seedEntry(db);
    expect(errorCode(() => humanChange(db, { op: 'add', title: 'only' }, T1))).toBe('invalid');
    expect(
      errorCode(() => humanChange(db, { op: 'edit', entry_id: seeded.id, body: 'only' }, T1))
    ).toBe('invalid');
    expect(errorCode(() => humanChange(db, { op: 'retire', entry_id: 999 }, T1))).toBe('invalid');
    expect(listProposals(db)).toHaveLength(1);
    expect(listEntries(db)).toEqual([seeded]);
    db.close();
  });

  it("a retire proposal records the entry's text, not the caller's", () => {
    const db = openLensDb(':memory:');
    const seeded = seedEntry(db);
    for (const text of [
      { title: 'Another entry', body: 'something else' },
      { title: '', body: '' },
    ]) {
      const created = createProposal(
        db,
        { ...addInput(), ...text, op: 'retire', entry_id: seeded.id },
        T1
      );
      expect(created).toMatchObject({ title: 'Seed', body: 'seed body' });
    }
    db.close();
  });

  it("accepting a retire re-copies the entry's current text", () => {
    const db = openLensDb(':memory:');
    const seeded = seedEntry(db);
    const created = createProposal(db, { ...addInput(), op: 'retire', entry_id: seeded.id }, T1);
    humanChange(db, { op: 'edit', entry_id: seeded.id, title: 'Now', body: 'current body' }, T1);
    const { proposal, entry } = acceptProposal(
      db,
      created.id,
      { title: 'caller title', body: '' },
      T2
    );
    expect(proposal).toMatchObject({ title: 'Now', body: 'current body', edited_on_accept: 0 });
    expect(entry).toMatchObject({ title: 'Now', body: 'current body', status: 'retired' });
    db.close();
  });

  it('retire removes the id from activeEntryIds', () => {
    const db = openLensDb(':memory:');
    const seeded = seedEntry(db);
    expect(activeEntryIds(db)).toEqual(new Set([seeded.id]));
    humanChange(db, { op: 'retire', entry_id: seeded.id }, T1);
    expect(activeEntryIds(db)).toEqual(new Set());
    expect(listEntries(db, { status: 'active' })).toEqual([]);
    expect(listEntries(db, { status: 'retired' }).map((e) => e.id)).toEqual([seeded.id]);
    db.close();
  });

  it('lists entries by id and proposals newest first, filtered by status', () => {
    const db = openLensDb(':memory:');
    const first = createProposal(db, addInput(), T1);
    const second = createProposal(db, addInput(), T2);
    const oldest = createProposal(db, addInput(), T0);
    expect(listProposals(db).map((p) => p.id)).toEqual([second.id, first.id, oldest.id]);
    const a = acceptProposal(db, second.id, null, T2).entry;
    const b = acceptProposal(db, first.id, null, T2).entry;
    expect(listEntries(db).map((e) => e.id)).toEqual([a.id, b.id]);
    expect(listProposals(db, { status: 'pending' }).map((p) => p.id)).toEqual([oldest.id]);
    db.close();
  });

  it('evidence round-trips as an object', () => {
    const db = openLensDb(':memory:');
    const created = createProposal(db, addInput(), T0);
    expect(created.evidence).toEqual({ finding_ids: [1, 2], history_ids: [3] });
    expect(listProposals(db)[0].evidence).toEqual({ finding_ids: [1, 2], history_ids: [3] });
    db.close();
  });
});

describe('operatorBackedEntryIds', () => {
  // An entry as the seeder makes it: an accepted `default` add.
  function defaultEntry(db: Db) {
    const created = createProposal(db, addInput('default'), T0);
    return acceptProposal(db, created.id, null, T0).entry;
  }

  const edit = (db: Db, entryId: number, proposed_by: ProposedBy, at: string) =>
    createProposal(db, { ...addInput(proposed_by), op: 'edit', entry_id: entryId }, at);

  it('includes entries added by the operator or an accepted ai proposal, not defaults', () => {
    const db = openLensDb(':memory:');
    const human = seedEntry(db);
    const ai = acceptProposal(db, createProposal(db, addInput('ai'), T0).id, null, T1).entry;
    defaultEntry(db);
    expect(operatorBackedEntryIds(db)).toEqual(new Set([human.id, ai.id]));
    db.close();
  });

  it('follows the latest accepted change to a default', () => {
    const db = openLensDb(':memory:');
    const { id } = defaultEntry(db);
    const pending = edit(db, id, 'ai', T0);
    expect(operatorBackedEntryIds(db).has(id)).toBe(false);

    acceptProposal(db, pending.id, null, T1);
    expect(operatorBackedEntryIds(db).has(id)).toBe(true);

    acceptProposal(db, edit(db, id, 'default', T2).id, null, T2);
    expect(operatorBackedEntryIds(db).has(id)).toBe(false);
    db.close();
  });

  it('orders by decision time, not creation order, and ignores rejected proposals', () => {
    const db = openLensDb(':memory:');
    const { id } = defaultEntry(db);
    const early = edit(db, id, 'ai', T0);
    const later = edit(db, id, 'default', T0);
    acceptProposal(db, later.id, null, T1);
    acceptProposal(db, early.id, null, T2);
    expect(operatorBackedEntryIds(db).has(id)).toBe(true);

    rejectProposal(db, edit(db, id, 'default', T2).id, null, T2);
    expect(operatorBackedEntryIds(db).has(id)).toBe(true);
    db.close();
  });

  it('a default update accepted with edited text makes the entry operator-backed', () => {
    for (const edits of [{ title: 'My title' }, { body: 'my host' }]) {
      const db = openLensDb(':memory:');
      const { id } = defaultEntry(db);
      const update = edit(db, id, 'default', T1);
      const { proposal } = acceptProposal(db, update.id, edits, T2);
      expect(proposal).toMatchObject({ proposed_by: 'default', edited_on_accept: 1 });
      expect(operatorBackedEntryIds(db).has(id)).toBe(true);
      db.close();
    }
  });

  it('a default update accepted as proposed leaves it default', () => {
    const db = openLensDb(':memory:');
    const { id } = defaultEntry(db);
    const first = acceptProposal(db, edit(db, id, 'default', T0).id, null, T0);
    expect(first.proposal.edited_on_accept).toBe(0);
    expect(operatorBackedEntryIds(db).has(id)).toBe(false);

    // An entry the operator edited, then a default bump accepted as proposed.
    humanChange(db, { op: 'edit', entry_id: id, title: 'Mine', body: 'my host' }, T1);
    expect(operatorBackedEntryIds(db).has(id)).toBe(true);
    acceptProposal(db, edit(db, id, 'default', T2).id, null, T2);
    expect(operatorBackedEntryIds(db).has(id)).toBe(false);
    db.close();
  });

  it("edits identical to the proposal don't count", () => {
    const db = openLensDb(':memory:');
    const { id } = defaultEntry(db);
    const update = edit(db, id, 'default', T1);
    const { proposal } = acceptProposal(
      db,
      update.id,
      { title: update.title, body: update.body },
      T2
    );
    expect(proposal.edited_on_accept).toBe(0);
    expect(operatorBackedEntryIds(db).has(id)).toBe(false);
    db.close();
  });

  it('excludes retired entries', () => {
    const db = openLensDb(':memory:');
    const { id } = seedEntry(db);
    humanChange(db, { op: 'retire', entry_id: id }, T1);
    expect(operatorBackedEntryIds(db)).toEqual(new Set());
    db.close();
  });
});
