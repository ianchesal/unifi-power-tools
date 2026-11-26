import { atomically } from '../analysis/pipeline.js';
import type { LensDb } from './lensDb.js';

// Site-knowledge entries and the proposals that change them. Entries only change
// by accepting a proposal, so the proposal table is the playbook's change log.

export type EntryStatus = 'active' | 'retired';
export type ProposalOp = 'add' | 'edit' | 'retire';
export type ProposalStatus = 'pending' | 'accepted' | 'rejected';
export type ProposedBy = 'ai' | 'human' | 'default';

export interface PlaybookEntry {
  id: number;
  title: string;
  body: string;
  status: EntryStatus;
  created_at: string;
  updated_at: string;
  source_proposal_id: number | null;
  default_key: string | null;
}

export interface Evidence {
  finding_ids: number[];
  history_ids: number[];
}

export interface PlaybookProposal {
  id: number;
  op: ProposalOp;
  entry_id: number | null;
  title: string;
  body: string;
  rationale: string;
  evidence: Evidence;
  status: ProposalStatus;
  proposed_by: ProposedBy;
  created_at: string;
  decided_at: string | null;
  decision_note: string | null;
}

export class ProposalError extends Error {
  readonly code: 'not_found' | 'conflict' | 'invalid';

  constructor(code: ProposalError['code'], message: string) {
    super(message);
    this.name = 'ProposalError';
    this.code = code;
  }
}

type ProposalRow = Omit<PlaybookProposal, 'evidence'> & { evidence: string };

function toProposal(row: ProposalRow): PlaybookProposal {
  return { ...row, evidence: JSON.parse(row.evidence) as Evidence };
}

function findEntry(db: LensDb, id: number): PlaybookEntry | null {
  const row = db.conn.prepare('SELECT * FROM playbook_entries WHERE id = ?').get(id);
  return (row as unknown as PlaybookEntry | undefined) ?? null;
}

export function listEntries(db: LensDb, opts: { status?: EntryStatus } = {}): PlaybookEntry[] {
  const where = opts.status ? 'WHERE status = ?' : '';
  return db.conn
    .prepare(`SELECT * FROM playbook_entries ${where} ORDER BY id`)
    .all(...(opts.status ? [opts.status] : [])) as unknown as PlaybookEntry[];
}

export function activeEntryIds(db: LensDb): Set<number> {
  return new Set(listEntries(db, { status: 'active' }).map((e) => e.id));
}

// Active entries whose current text is not a shipped default: the latest accepted
// change to each came from the operator, or from an AI proposal they approved.
// An add proposal has no entry_id, so the entry's source_proposal_id links it.
export function operatorBackedEntryIds(db: LensDb): Set<number> {
  const rows = db.conn
    .prepare(
      `SELECT e.id FROM playbook_entries e
       WHERE e.status = 'active' AND (
         SELECT p.proposed_by FROM playbook_proposals p
         WHERE p.status = 'accepted' AND (p.entry_id = e.id OR p.id = e.source_proposal_id)
         ORDER BY p.decided_at DESC, p.id DESC LIMIT 1
       ) != 'default'`
    )
    .all() as { id: number }[];
  return new Set(rows.map((r) => r.id));
}

// Marks an entry as the one seeded from a shipped default.
export function setEntryDefaultKey(db: LensDb, entryId: number, key: string): void {
  db.conn.prepare('UPDATE playbook_entries SET default_key = ? WHERE id = ?').run(key, entryId);
}

function assertText(op: ProposalOp, title: string, body: string): void {
  if (op === 'retire') return;
  if (title.trim() === '' || body.trim() === '') {
    throw new ProposalError('invalid', `title and body are required to ${op} an entry`);
  }
}

// The entry an edit or retire acts on.
function targetEntry(db: LensDb, op: ProposalOp, entryId: number | null): PlaybookEntry {
  const entry = entryId === null ? null : findEntry(db, entryId);
  if (!entry) {
    throw new ProposalError('invalid', `${op} needs the entry_id of an existing entry`);
  }
  return entry;
}

export function createProposal(
  db: LensDb,
  p: {
    op: ProposalOp;
    entry_id?: number | null;
    title: string;
    body: string;
    rationale: string;
    evidence: Evidence;
    proposed_by: ProposedBy;
  },
  nowIso: string
): PlaybookProposal {
  const entryId = p.entry_id ?? null;
  assertText(p.op, p.title, p.body);
  if (p.op !== 'add') targetEntry(db, p.op, entryId);
  else if (entryId !== null) {
    throw new ProposalError('invalid', 'add must not name an entry_id');
  }
  const row = db.conn
    .prepare(
      `INSERT INTO playbook_proposals
         (op, entry_id, title, body, rationale, evidence, status, proposed_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?) RETURNING *`
    )
    .get(
      p.op,
      entryId,
      p.title,
      p.body,
      p.rationale,
      JSON.stringify(p.evidence),
      p.proposed_by,
      nowIso
    );
  return toProposal(row as unknown as ProposalRow);
}

export function listProposals(
  db: LensDb,
  opts: { status?: ProposalStatus } = {}
): PlaybookProposal[] {
  const where = opts.status ? 'WHERE status = ?' : '';
  const rows = db.conn
    .prepare(`SELECT * FROM playbook_proposals ${where} ORDER BY created_at DESC, id DESC`)
    .all(...(opts.status ? [opts.status] : [])) as unknown as ProposalRow[];
  return rows.map(toProposal);
}

function pendingProposal(db: LensDb, id: number): PlaybookProposal {
  const row = db.conn.prepare('SELECT * FROM playbook_proposals WHERE id = ?').get(id) as unknown as
    | ProposalRow
    | undefined;
  if (!row) throw new ProposalError('not_found', `Proposal ${id} not found`);
  if (row.status !== 'pending') {
    throw new ProposalError('conflict', `Proposal ${id} is already ${row.status}`);
  }
  return toProposal(row);
}

function applyToEntries(db: LensDb, p: PlaybookProposal, nowIso: string): PlaybookEntry {
  if (p.op === 'add') {
    return db.conn
      .prepare(
        `INSERT INTO playbook_entries
           (title, body, status, created_at, updated_at, source_proposal_id)
         VALUES (?, ?, 'active', ?, ?, ?) RETURNING *`
      )
      .get(p.title, p.body, nowIso, nowIso, p.id) as unknown as PlaybookEntry;
  }
  const { id } = targetEntry(db, p.op, p.entry_id);
  if (p.op === 'edit') {
    return db.conn
      .prepare(
        `UPDATE playbook_entries SET title = ?, body = ?, status = 'active', updated_at = ?
         WHERE id = ? RETURNING *`
      )
      .get(p.title, p.body, nowIso, id) as unknown as PlaybookEntry;
  }
  return db.conn
    .prepare(
      `UPDATE playbook_entries SET status = 'retired', updated_at = ? WHERE id = ? RETURNING *`
    )
    .get(nowIso, id) as unknown as PlaybookEntry;
}

// `edits` override the proposal's text; the proposal row keeps what was applied.
export function acceptProposal(
  db: LensDb,
  id: number,
  edits: { title?: string; body?: string } | null,
  nowIso: string
): { proposal: PlaybookProposal; entry: PlaybookEntry } {
  return atomically(db, () => {
    const pending = pendingProposal(db, id);
    const applied = {
      ...pending,
      title: edits?.title ?? pending.title,
      body: edits?.body ?? pending.body,
    };
    assertText(applied.op, applied.title, applied.body);
    const entry = applyToEntries(db, applied, nowIso);
    const row = db.conn
      .prepare(
        `UPDATE playbook_proposals SET status = 'accepted', title = ?, body = ?, decided_at = ?
         WHERE id = ? RETURNING *`
      )
      .get(applied.title, applied.body, nowIso, id);
    return { proposal: toProposal(row as unknown as ProposalRow), entry };
  });
}

export function rejectProposal(
  db: LensDb,
  id: number,
  note: string | null,
  nowIso: string
): PlaybookProposal {
  return atomically(db, () => {
    pendingProposal(db, id);
    const row = db.conn
      .prepare(
        `UPDATE playbook_proposals SET status = 'rejected', decision_note = ?, decided_at = ?
         WHERE id = ? RETURNING *`
      )
      .get(note, nowIso, id);
    return toProposal(row as unknown as ProposalRow);
  });
}

// A direct operator change: recorded as a proposal and accepted at once.
export function humanChange(
  db: LensDb,
  p: {
    op: ProposalOp;
    entry_id?: number | null;
    title?: string;
    body?: string;
    rationale?: string;
  },
  nowIso: string
): { proposal: PlaybookProposal; entry: PlaybookEntry } {
  return atomically(db, () => {
    // A retire needs no text from the caller: record what is being retired.
    const current = p.op === 'retire' ? targetEntry(db, p.op, p.entry_id ?? null) : null;
    const created = createProposal(
      db,
      {
        op: p.op,
        entry_id: p.entry_id,
        title: p.title ?? current?.title ?? '',
        body: p.body ?? current?.body ?? '',
        rationale: p.rationale ?? '',
        evidence: { finding_ids: [], history_ids: [] },
        proposed_by: 'human',
      },
      nowIso
    );
    return acceptProposal(db, created.id, null, nowIso);
  });
}
