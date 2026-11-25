import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { openSinkDb, verifySchema, type SinkDb } from '../../src/db/sinkDb.js';

const FIXTURE = 'tests/fixtures/events.db';

describe('openSinkDb', () => {
  it('opens the fixture read-only', () => {
    const db = openSinkDb(FIXTURE);
    expect(() => db.conn.prepare('DELETE FROM events').run()).toThrow();
  });

  it('verifySchema passes against the real sink schema', () => {
    const db = openSinkDb(FIXTURE);
    const result = verifySchema(db);
    expect(result.ok).toBe(true);
    expect(result.missingColumns).toEqual([]);
  });

  it('verifySchema flags missing columns', () => {
    const conn = new DatabaseSync(':memory:');
    conn.exec('CREATE TABLE events (id INTEGER PRIMARY KEY, category TEXT)');
    const db: SinkDb = { conn };
    const result = verifySchema(db);
    expect(result.ok).toBe(false);
    expect(result.missingColumns).toContain('source_ip');
  });

  it('verifySchema requires the sink v1.0.3 client columns', () => {
    const conn = new DatabaseSync(':memory:');
    conn.exec(
      `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
       category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
       dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
       signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER)`
    );
    const result = verifySchema({ conn });
    expect(result.ok).toBe(false);
    expect(result.missingColumns).toEqual([
      'source_client_name',
      'source_client_mac',
      'dest_client_name',
      'dest_client_mac',
    ]);
  });
});
