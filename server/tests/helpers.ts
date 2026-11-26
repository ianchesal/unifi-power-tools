import type { RunnerDeps } from '../src/analysis/runner.js';
import type { LensDb } from '../src/db/lensDb.js';
import { type EventsDb, openEventsDb } from '../src/db/eventsDb.js';

export interface EventRowFixture {
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

// In-memory events DB built by the real migrations, so tests track the real schema.
export function seededEventsDb(rows: EventRowFixture[]): EventsDb {
  const { conn } = openEventsDb(':memory:').writer;
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
  eventsDb: EventsDb,
  lensDb: LensDb,
  overrides: Partial<RunnerDeps> = {}
): RunnerDeps {
  return {
    eventsDb,
    lensDb,
    lanCidrs: [],
    trustedAdminNames: [],
    safeSignaturePrefixes: ['ET DROP', 'ET CINS'],
    ...overrides,
  };
}
