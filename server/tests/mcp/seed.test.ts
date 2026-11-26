import { describe, expect, it } from 'vitest';
import { openLensDb } from '../../src/db/lensDb.js';
import {
  createProposal,
  humanChange,
  listEntries,
  listProposals,
} from '../../src/db/playbookStore.js';
import { PLAYBOOK_DEFAULTS, type PlaybookDefault } from '../../src/mcp/playbook/defaults.js';
import { seedPlaybookDefaults } from '../../src/mcp/playbook/seed.js';

const T0 = '2026-01-01T00:00:00.000Z';
const T1 = '2026-01-02T00:00:00.000Z';
const T2 = '2026-01-03T00:00:00.000Z';

const A: PlaybookDefault = { key: 'a', version: 1, title: 'A', body: 'a v1' };
const B: PlaybookDefault = { key: 'b', version: 1, title: 'B', body: 'b v1' };
const DEFAULTS = [A, B];

const bumpA = (version: number): PlaybookDefault => ({
  ...A,
  version,
  title: `A v${version}`,
  body: `a v${version}`,
});

type Db = ReturnType<typeof openLensDb>;

function seeded(): Db {
  const db = openLensDb(':memory:');
  seedPlaybookDefaults(db, DEFAULTS, T0);
  return db;
}

function entry(db: Db, key: string) {
  const found = listEntries(db).find((e) => e.default_key === key);
  if (!found) throw new Error(`no entry for ${key}`);
  return found;
}

describe('seedPlaybookDefaults', () => {
  it('first run inserts each default as an active entry with its key', () => {
    const db = openLensDb(':memory:');
    expect(seedPlaybookDefaults(db, DEFAULTS, T0)).toEqual({ inserted: 2, proposed: 0 });
    expect(listEntries(db).map((e) => [e.default_key, e.title, e.body, e.status])).toEqual([
      ['a', 'A', 'a v1', 'active'],
      ['b', 'B', 'b v1', 'active'],
    ]);
    const proposals = listProposals(db);
    expect(proposals).toHaveLength(2);
    for (const p of proposals) {
      expect(p).toMatchObject({
        op: 'add',
        status: 'accepted',
        proposed_by: 'default',
        decided_at: T0,
      });
    }
    db.close();
  });

  it('second run with the same versions changes nothing', () => {
    const db = seeded();
    const entries = listEntries(db);
    const proposals = listProposals(db);
    expect(seedPlaybookDefaults(db, DEFAULTS, T1)).toEqual({ inserted: 0, proposed: 0 });
    expect(listEntries(db)).toEqual(entries);
    expect(listProposals(db)).toEqual(proposals);
    db.close();
  });

  it('operator edits survive a re-run', () => {
    const db = seeded();
    humanChange(db, { op: 'edit', entry_id: entry(db, 'a').id, title: 'A', body: 'mine' }, T1);
    seedPlaybookDefaults(db, DEFAULTS, T2);
    expect(entry(db, 'a').body).toBe('mine');
    db.close();
  });

  it('a version bump creates one pending edit proposal and leaves the entry untouched', () => {
    const db = seeded();
    const before = entry(db, 'a');
    expect(seedPlaybookDefaults(db, [bumpA(2), B], T1)).toEqual({ inserted: 0, proposed: 1 });
    const pending = listProposals(db, { status: 'pending' });
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({
      op: 'edit',
      entry_id: before.id,
      title: 'A v2',
      body: 'a v2',
      proposed_by: 'default',
      created_at: T1,
    });
    expect(entry(db, 'a')).toEqual(before);
    // The handled version is recorded, so the next start proposes nothing new.
    expect(seedPlaybookDefaults(db, [bumpA(2), B], T2)).toEqual({ inserted: 0, proposed: 0 });
    expect(listProposals(db, { status: 'pending' })).toEqual(pending);
    db.close();
  });

  it('a second bump supersedes the still-pending proposal', () => {
    const db = seeded();
    seedPlaybookDefaults(db, [bumpA(2), B], T1);
    const v2 = listProposals(db, { status: 'pending' })[0];
    expect(seedPlaybookDefaults(db, [bumpA(3), B], T2)).toEqual({ inserted: 0, proposed: 1 });
    const pending = listProposals(db, { status: 'pending' });
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({ body: 'a v3', proposed_by: 'default' });
    const old = listProposals(db).find((p) => p.id === v2.id);
    expect(old).toMatchObject({ status: 'rejected', decided_at: T2 });
    expect(old?.decision_note).toMatch(/Superseded by default version 3/);
    db.close();
  });

  it('a bump leaves other pending proposals for the entry alone', () => {
    const db = seeded();
    const ai = createProposal(
      db,
      {
        op: 'edit',
        entry_id: entry(db, 'a').id,
        title: 'A',
        body: 'ai idea',
        rationale: 'seen',
        evidence: { finding_ids: [1], history_ids: [] },
        proposed_by: 'ai',
      },
      T0
    );
    seedPlaybookDefaults(db, [bumpA(2), B], T1);
    expect(listProposals(db).find((p) => p.id === ai.id)?.status).toBe('pending');
    db.close();
  });

  it('a retired default still gets the bump proposal', () => {
    const db = seeded();
    const { id } = entry(db, 'a');
    humanChange(db, { op: 'retire', entry_id: id }, T1);
    expect(seedPlaybookDefaults(db, [bumpA(2), B], T2)).toEqual({ inserted: 0, proposed: 1 });
    expect(listProposals(db, { status: 'pending' })[0].entry_id).toBe(id);
    expect(entry(db, 'a').status).toBe('retired');
    db.close();
  });

  it('a default removed from code leaves its entry alone', () => {
    const db = seeded();
    const before = entry(db, 'b');
    expect(seedPlaybookDefaults(db, [A], T1)).toEqual({ inserted: 0, proposed: 0 });
    expect(entry(db, 'b')).toEqual(before);
    expect(before.status).toBe('active');
    db.close();
  });

  it('a bump for a key whose entry is gone is skipped without blocking the others', () => {
    const db = seeded();
    db.conn.prepare("DELETE FROM playbook_entries WHERE default_key = 'a'").run();
    const c: PlaybookDefault = { key: 'c', version: 1, title: 'C', body: 'c v1' };
    expect(seedPlaybookDefaults(db, [bumpA(2), c], T1)).toEqual({ inserted: 1, proposed: 0 });
    expect(entry(db, 'c').status).toBe('active');
    db.close();
  });
});

describe('shipped defaults', () => {
  it('are the five spec entries, all at version 1', () => {
    expect(PLAYBOOK_DEFAULTS.map((d) => [d.key, d.version])).toEqual([
      ['blocked-scanner-fingerprints', 1],
      ['git-ssh-to-github', 1],
      ['vpn-client-exploit-sigs', 1],
      ['device-status-events', 1],
      ['blocked-exploits-on-forwarded-service', 1],
    ]);
  });

  it('are generic', () => {
    // GitHub's published SSH range is a public address block, not a site address.
    const GITHUB_SSH_RANGE = '140.82.112.0/20';
    expect(new Set(PLAYBOOK_DEFAULTS.map((d) => d.key)).size).toBe(PLAYBOOK_DEFAULTS.length);
    for (const d of PLAYBOOK_DEFAULTS) {
      expect(Number.isInteger(d.version) && d.version >= 1).toBe(true);
      const ips = `${d.title}\n${d.body}`.match(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?/g) ?? [];
      for (const ip of ips.filter((i) => i !== GITHUB_SSH_RANGE)) {
        expect(ip).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\./);
      }
    }
  });

  it('limits the VPN default to hosts a site entry names', () => {
    const vpn = PLAYBOOK_DEFAULTS.find((d) => d.key === 'vpn-client-exploit-sigs');
    expect(vpn?.body).toMatch(/only (if|when) another site entry names the source host/i);
  });

  it('seed into an empty database', () => {
    const db = openLensDb(':memory:');
    expect(seedPlaybookDefaults(db, PLAYBOOK_DEFAULTS, T0)).toEqual({ inserted: 5, proposed: 0 });
    db.close();
  });
});
