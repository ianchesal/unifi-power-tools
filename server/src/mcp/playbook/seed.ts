import { atomically } from '../../analysis/pipeline.js';
import type { LensDb } from '../../db/lensDb.js';
import {
  acceptProposal,
  createProposal,
  listEntries,
  listProposals,
  rejectProposal,
  setEntryDefaultKey,
} from '../../db/playbookStore.js';
import type { PlaybookDefault } from './defaults.js';

const NO_EVIDENCE = { finding_ids: [], history_ids: [] };

function seenVersion(db: LensDb, key: string): number | null {
  const row = db.conn
    .prepare('SELECT version FROM playbook_defaults_seen WHERE default_key = ?')
    .get(key) as { version: number } | undefined;
  return row?.version ?? null;
}

function markSeen(db: LensDb, key: string, version: number): void {
  db.conn
    .prepare(
      `INSERT INTO playbook_defaults_seen (default_key, version) VALUES (?, ?)
       ON CONFLICT (default_key) DO UPDATE SET version = excluded.version`
    )
    .run(key, version);
}

function insertDefault(db: LensDb, d: PlaybookDefault, nowIso: string): void {
  const proposal = createProposal(
    db,
    {
      op: 'add',
      title: d.title,
      body: d.body,
      rationale: `Shipped default "${d.key}", version ${d.version}.`,
      evidence: NO_EVIDENCE,
      proposed_by: 'default',
    },
    nowIso
  );
  const { entry } = acceptProposal(db, proposal.id, null, nowIso);
  setEntryDefaultKey(db, entry.id, d.key);
}

// Offers a newer default text as an edit the operator decides on. Returns false
// when the key's entry no longer exists, so there is nothing to edit.
function proposeUpdate(db: LensDb, d: PlaybookDefault, nowIso: string): boolean {
  const entry = listEntries(db).find((e) => e.default_key === d.key);
  if (!entry) return false;
  const stale = listProposals(db, { status: 'pending' }).filter(
    (p) => p.proposed_by === 'default' && p.entry_id === entry.id
  );
  for (const p of stale) {
    rejectProposal(db, p.id, `Superseded by default version ${d.version}`, nowIso);
  }
  createProposal(
    db,
    {
      op: 'edit',
      entry_id: entry.id,
      title: d.title,
      body: d.body,
      rationale: `Shipped default "${d.key}" changed in version ${d.version}. Accept to replace the current text, or reject to keep it.`,
      evidence: NO_EVIDENCE,
      proposed_by: 'default',
    },
    nowIso
  );
  return true;
}

// Run at startup. A new default becomes an active entry; a newer version of a
// seen one becomes a pending proposal, so operator edits are never overwritten.
export function seedPlaybookDefaults(
  db: LensDb,
  defaults: PlaybookDefault[],
  nowIso: string
): { inserted: number; proposed: number } {
  return atomically(db, () => {
    let inserted = 0;
    let proposed = 0;
    for (const d of defaults) {
      const seen = seenVersion(db, d.key);
      if (seen !== null && seen >= d.version) continue;
      if (seen === null) {
        insertDefault(db, d, nowIso);
        inserted++;
      } else if (proposeUpdate(db, d, nowIso)) {
        proposed++;
      }
      markSeen(db, d.key, d.version);
    }
    return { inserted, proposed };
  });
}
