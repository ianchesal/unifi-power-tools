import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export interface LensDb {
  conn: DatabaseSync;
  close(): void;
}

const MIGRATIONS: { version: number; sql: string }[] = [
  {
    version: 1,
    sql: `
      CREATE TABLE baselines (
        category TEXT NOT NULL,
        signature TEXT NOT NULL,
        day TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (category, signature, day)
      );
      CREATE TABLE seen_signatures (
        category TEXT NOT NULL,
        signature TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        PRIMARY KEY (category, signature)
      );
      CREATE TABLE seen_source_ips (
        source_ip TEXT NOT NULL PRIMARY KEY,
        first_seen TEXT NOT NULL
      );
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
    `,
  },
  {
    version: 2,
    sql: `ALTER TABLE analysis_requests ADD COLUMN source TEXT NOT NULL DEFAULT 'ai';`,
  },
  {
    version: 3,
    sql: `CREATE TABLE seen_clients (mac TEXT NOT NULL PRIMARY KEY, first_seen TEXT NOT NULL);`,
  },
  {
    // Triage redesign: new/acknowledged/dismissed/resolved -> triaging/attention/closed.
    // Order matters: the history insert and the dismissed/resolved mappings read the
    // legacy status, so they run before the status rewrite.
    version: 4,
    sql: `
      ALTER TABLE findings ADD COLUMN closed_by TEXT;
      ALTER TABLE findings ADD COLUMN closed_reason TEXT;
      ALTER TABLE findings ADD COLUMN closed_at TEXT;
      ALTER TABLE findings ADD COLUMN last_activity_at TEXT NOT NULL DEFAULT '';
      ALTER TABLE findings ADD COLUMN last_triaged_at TEXT;
      ALTER TABLE findings ADD COLUMN reopen_count INTEGER NOT NULL DEFAULT 0;

      ALTER TABLE analysis_requests ADD COLUMN verdict TEXT;
      ALTER TABLE analysis_requests ADD COLUMN summary TEXT;
      ALTER TABLE analysis_requests ADD COLUMN recommended_action TEXT;
      ALTER TABLE analysis_requests ADD COLUMN why_now TEXT;
      ALTER TABLE analysis_requests ADD COLUMN cited_entries TEXT;
      ALTER TABLE analysis_requests ADD COLUMN is_recheck INTEGER NOT NULL DEFAULT 0;

      CREATE TABLE finding_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL REFERENCES findings(id),
        at TEXT NOT NULL,
        kind TEXT NOT NULL,
        actor TEXT NOT NULL,
        summary TEXT NOT NULL,
        note TEXT,
        analysis_request_id INTEGER,
        feedback_considered_at TEXT
      );
      CREATE INDEX idx_finding_history_finding ON finding_history(finding_id);

      INSERT INTO finding_history (finding_id, at, kind, actor, summary)
        SELECT id, first_seen, 'created', 'system', 'Migrated in triage redesign (was ' || status || ')'
        FROM findings;

      UPDATE findings SET
        closed_by = COALESCE(
          (SELECT r.source FROM analysis_requests r
             WHERE r.finding_id = findings.id AND r.status = 'answered'
             ORDER BY r.answered_at DESC, r.id DESC LIMIT 1),
          'human'),
        closed_reason = COALESCE(
          (SELECT r.recommendation FROM analysis_requests r
             WHERE r.finding_id = findings.id AND r.status = 'answered'
             ORDER BY r.answered_at DESC, r.id DESC LIMIT 1),
          'Dismissed before triage redesign'),
        closed_at = COALESCE(
          (SELECT MAX(r.answered_at) FROM analysis_requests r
             WHERE r.finding_id = findings.id AND r.status = 'answered'),
          last_seen),
        status = 'closed'
      WHERE status = 'dismissed';

      UPDATE findings SET
        closed_by = 'system',
        closed_reason = 'Condition cleared (pre-redesign auto-resolve)',
        closed_at = last_seen,
        status = 'closed'
      WHERE status = 'resolved';

      UPDATE findings SET status = 'attention' WHERE status = 'acknowledged';
      UPDATE findings SET status = 'triaging' WHERE status = 'new';

      UPDATE analysis_requests SET status = 'cancelled'
        WHERE status = 'pending'
          AND finding_id IN (SELECT id FROM findings WHERE status IN ('closed', 'attention'));

      INSERT INTO analysis_requests (finding_id, status, context, created_at)
        SELECT id, 'pending', '{}', last_seen FROM findings
        WHERE status = 'triaging'
          AND NOT EXISTS (
            SELECT 1 FROM analysis_requests r WHERE r.finding_id = findings.id AND r.status = 'pending');

      -- Anchor closed rows at the migration time (closed_at, if later) so only
      -- activity after the upgrade makes them due for a recheck; closed_at stays.
      UPDATE findings SET
        last_activity_at = MAX(closed_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        last_triaged_at = MAX(closed_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      WHERE status = 'closed';
      UPDATE findings SET last_activity_at = last_seen, last_triaged_at = last_seen WHERE status = 'attention';
      UPDATE findings SET last_activity_at = last_seen WHERE status = 'triaging';
    `,
  },
];

export function openLensDb(path: string): LensDb {
  if (path !== ':memory:') {
    const dir = dirname(path);
    if (dir && dir !== '.') mkdirSync(dir, { recursive: true });
  }

  const conn = new DatabaseSync(path);
  conn.exec('PRAGMA journal_mode = WAL;');
  conn.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);');

  const applied = new Set(
    (conn.prepare('SELECT version FROM schema_migrations').all() as { version: number }[]).map(
      (row) => row.version
    )
  );

  for (const migration of MIGRATIONS) {
    if (applied.has(migration.version)) continue;
    conn.exec('BEGIN');
    try {
      conn.exec(migration.sql);
      conn.prepare('INSERT INTO schema_migrations (version) VALUES (?)').run(migration.version);
      conn.exec('COMMIT');
    } catch (err) {
      conn.exec('ROLLBACK');
      throw err;
    }
  }

  return {
    conn,
    close: () => {
      if (conn.isOpen) conn.close();
    },
  };
}
