import { DatabaseSync } from 'node:sqlite';
import type { RunnerDeps } from '../src/analysis/runner.js';
import type { LensDb } from '../src/db/lensDb.js';
import type { SinkDb } from '../src/db/sinkDb.js';

export interface SinkEventRow {
  received_at: string;
  category: string;
  signature?: string | null;
  source_ip?: string | null;
  action?: string | null;
  message?: string | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  source_client_mac?: string | null;
  source_client_name?: string | null;
}

// In-memory sink DB with the full sink v1.0.3 `events` schema (every column in
// sinkDb.ts's EXPECTED_COLUMNS, including the client-identity columns).
export function seededSinkDb(rows: SinkEventRow[]): SinkDb {
  const conn = new DatabaseSync(':memory:');
  conn.exec(
    `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
     category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
     dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
     signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER,
     source_client_name TEXT, source_client_mac TEXT, dest_client_name TEXT, dest_client_mac TEXT)`
  );
  const stmt = conn.prepare(
    `INSERT INTO events (received_at, category, signature, source_ip, action, message,
                         dest_ip, dest_port, source_client_mac, source_client_name, raw, parsed)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'raw-line', 1)`
  );
  for (const r of rows) {
    stmt.run(
      r.received_at,
      r.category,
      r.signature ?? null,
      r.source_ip ?? null,
      r.action ?? null,
      r.message ?? null,
      r.dest_ip ?? null,
      r.dest_port ?? null,
      r.source_client_mac ?? null,
      r.source_client_name ?? null
    );
  }
  return { conn };
}

export function runnerDeps(
  sinkDb: SinkDb,
  lensDb: LensDb,
  overrides: Partial<RunnerDeps> = {}
): RunnerDeps {
  return {
    sinkDb,
    lensDb,
    lanCidrs: [],
    trustedAdminNames: [],
    safeSignaturePrefixes: ['ET DROP', 'ET CINS'],
    ...overrides,
  };
}
