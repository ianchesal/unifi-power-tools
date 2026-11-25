import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { openLensDb } from '../../src/db/lensDb.js';

describe('openLensDb', () => {
  it('creates all expected tables', () => {
    const db = openLensDb(':memory:');
    const tables = db.conn
      .prepare("SELECT name FROM sqlite_master WHERE type='table'")
      .all()
      .map((r: any) => r.name);
    for (const t of [
      'baselines',
      'seen_signatures',
      'seen_source_ips',
      'findings',
      'analysis_requests',
      'seen_clients',
      'finding_history',
    ]) {
      expect(tables).toContain(t);
    }
    db.close();
  });

  it('enforces one findings row per entity', () => {
    const db = openLensDb(':memory:');
    db.conn
      .prepare(
        `INSERT INTO findings (entity_type, entity_key, first_seen, last_seen, triggers, severity_score, status)
         VALUES ('source_ip', '1.2.3.4', 'a', 'a', '[]', 0, 'new')`
      )
      .run();
    expect(() =>
      db.conn
        .prepare(
          `INSERT INTO findings (entity_type, entity_key, first_seen, last_seen, triggers, severity_score, status)
           VALUES ('source_ip', '1.2.3.4', 'b', 'b', '[]', 0, 'new')`
        )
        .run()
    ).toThrow();
    db.close();
  });

  it('is idempotent across repeated opens on the same file', () => {
    const path = ':memory:';
    const db1 = openLensDb(path);
    db1.close();
    const db2 = openLensDb(path); // fresh :memory: db, but proves no migration crash on a second run pattern
    expect(db2.conn.prepare('SELECT COUNT(*) as n FROM findings').get()).toEqual({ n: 0 });
    db2.close();
  });

  it('gives analysis_requests a source column defaulting to ai', () => {
    const db = openLensDb(':memory:');
    db.conn
      .prepare(
        `INSERT INTO findings (entity_type, entity_key, first_seen, last_seen, triggers, severity_score, status)
         VALUES ('source_ip', '1.2.3.4', 'a', 'a', '[]', 0, 'new')`
      )
      .run();
    db.conn
      .prepare(
        `INSERT INTO analysis_requests (finding_id, status, context, created_at) VALUES (1, 'pending', '{}', 'a')`
      )
      .run();
    const row = db.conn.prepare('SELECT source FROM analysis_requests WHERE finding_id = 1').get() as {
      source: string;
    };
    expect(row.source).toBe('ai');
    db.close();
  });

  describe('migration 4 (triage redesign)', () => {
    const T3 = '2026-01-03T00:00:00.000Z';
    const T4 = '2026-01-04T00:00:00.000Z';
    const T5 = '2026-01-05T00:00:00.000Z';
    // A closed_at later than the migration run: the anchor keeps it.
    const FUTURE = '2999-01-01T00:00:00.000Z';
    const ISO_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
    // Hand-seeds a pre-migration (v1-v3) database, so openLensDb applies only v4.
    function seedLegacyDb(): string {
      const path = join(mkdtempSync(join(tmpdir(), 'lens-mig4-')), 'lens.db');
      const raw = new DatabaseSync(path);
      raw.exec(`
        CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
        CREATE TABLE baselines (
          category TEXT NOT NULL, signature TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL,
          PRIMARY KEY (category, signature, day)
        );
        CREATE TABLE seen_signatures (
          category TEXT NOT NULL, signature TEXT NOT NULL, first_seen TEXT NOT NULL,
          PRIMARY KEY (category, signature)
        );
        CREATE TABLE seen_source_ips (source_ip TEXT NOT NULL PRIMARY KEY, first_seen TEXT NOT NULL);
        CREATE TABLE findings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          entity_type TEXT NOT NULL,
          entity_key TEXT NOT NULL,
          first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL,
          triggers TEXT NOT NULL,
          severity_score REAL NOT NULL,
          status TEXT NOT NULL DEFAULT 'new',
          UNIQUE (entity_type, entity_key)
        );
        CREATE TABLE analysis_requests (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          finding_id INTEGER NOT NULL REFERENCES findings(id),
          status TEXT NOT NULL DEFAULT 'pending',
          context TEXT NOT NULL,
          recommendation TEXT,
          risk_level TEXT,
          created_at TEXT NOT NULL,
          answered_at TEXT
        );
        CREATE INDEX idx_analysis_requests_finding ON analysis_requests(finding_id);
        CREATE INDEX idx_analysis_requests_status ON analysis_requests(status);
        ALTER TABLE analysis_requests ADD COLUMN source TEXT NOT NULL DEFAULT 'ai';
        CREATE TABLE seen_clients (mac TEXT NOT NULL PRIMARY KEY, first_seen TEXT NOT NULL);
        INSERT INTO schema_migrations (version) VALUES (1), (2), (3);
      `);
      const ins = raw.prepare(
        `INSERT INTO findings (entity_type, entity_key, first_seen, last_seen, triggers, severity_score, status)
         VALUES ('source_ip', ?, ?, ?, '[]', 0, ?)`
      );
      ins.run('A', 'f1', 't2', 'dismissed'); // id 1
      ins.run('B', 'f1', T3, 'dismissed'); // id 2
      ins.run('C', 'f1', T4, 'resolved'); // id 3
      ins.run('D', 'f1', 't6', 'acknowledged'); // id 4
      ins.run('E', 'f1', 't7', 'new'); // id 5
      ins.run('F', 'f1', FUTURE, 'dismissed'); // id 6
      const req = raw.prepare(
        `INSERT INTO analysis_requests (finding_id, status, context, recommendation, source, created_at, answered_at)
         VALUES (?, ?, '{}', ?, ?, 'c', ?)`
      );
      req.run(1, 'answered', 'rule says', 'rule', T5);
      req.run(6, 'pending', null, 'ai', null);
      raw.close();
      return path;
    }

    const row = (db: ReturnType<typeof openLensDb>, key: string) =>
      db.conn.prepare('SELECT * FROM findings WHERE entity_key = ?').get(key) as any;

    it('maps legacy statuses and fills timestamps', () => {
      const path = seedLegacyDb();
      const before = new Date().toISOString();
      const db = openLensDb(path);
      const after = new Date().toISOString();
      expect(row(db, 'A')).toMatchObject({
        status: 'closed',
        closed_by: 'rule',
        closed_reason: 'rule says',
        closed_at: T5,
        reopen_count: 0,
      });
      expect(row(db, 'B')).toMatchObject({
        status: 'closed',
        closed_by: 'human',
        closed_reason: 'Dismissed before triage redesign',
        closed_at: T3,
      });
      expect(row(db, 'C')).toMatchObject({
        status: 'closed',
        closed_by: 'system',
        closed_reason: 'Condition cleared (pre-redesign auto-resolve)',
        closed_at: T4,
      });
      // Closed rows are anchored at the migration time (or closed_at, if later),
      // so only activity after the upgrade makes them due for a recheck.
      for (const key of ['A', 'B', 'C']) {
        const r = row(db, key);
        expect(r.last_activity_at).toMatch(ISO_Z);
        expect(r.last_triaged_at).toBe(r.last_activity_at);
        expect(r.last_activity_at >= r.closed_at).toBe(true);
        expect(r.last_activity_at >= before && r.last_activity_at <= after).toBe(true);
      }
      expect(row(db, 'F')).toMatchObject({
        status: 'closed',
        closed_at: FUTURE,
        last_activity_at: FUTURE,
        last_triaged_at: FUTURE,
      });
      expect(row(db, 'D')).toMatchObject({
        status: 'attention',
        closed_by: null,
        last_activity_at: 't6',
        last_triaged_at: 't6',
      });
      expect(row(db, 'E')).toMatchObject({
        status: 'triaging',
        last_activity_at: 't7',
        last_triaged_at: null,
      });
      db.close();
    });

    it('queues a pending request for every triaging finding and cancels stale ones', () => {
      const db = openLensDb(seedLegacyDb());
      const reqs = (id: number) =>
        db.conn
          .prepare('SELECT status, context, created_at FROM analysis_requests WHERE finding_id = ?')
          .all(id) as any[];
      expect(reqs(row(db, 'E').id)).toEqual([{ status: 'pending', context: '{}', created_at: 't7' }]);
      expect(reqs(row(db, 'F').id).map((r) => r.status)).toEqual(['cancelled']);
      expect(reqs(row(db, 'A').id).map((r) => r.status)).toEqual(['answered']);
      expect(reqs(row(db, 'D').id)).toEqual([]);
      db.close();
    });

    it('writes one created history row per finding noting the old status', () => {
      const db = openLensDb(seedLegacyDb());
      const rows = db.conn.prepare('SELECT * FROM finding_history ORDER BY finding_id').all() as any[];
      expect(rows).toHaveLength(6);
      expect(rows.every((r) => r.kind === 'created' && r.actor === 'system')).toBe(true);
      const d = rows.find((r) => r.finding_id === row(db, 'D').id);
      expect(d.summary).toContain('was acknowledged');
      expect(d.at).toBe('f1');
      db.close();
    });

    it('applies cleanly to an empty database', () => {
      const db = openLensDb(':memory:');
      expect(db.conn.prepare('SELECT * FROM finding_history').all()).toEqual([]);
      const cols = (db.conn.prepare('PRAGMA table_info(findings)').all() as any[]).map((c) => c.name);
      expect(cols).toContain('reopen_count');
      db.close();
    });
  });
});
