import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it, vi } from 'vitest';

// Today's only ignored key (siteactivity|2154) is outside
// CLIENT_SECURITY_CATEGORIES, so the client queries' ignored-signature clause
// can't fire against real data. Add an ignored key in a Security category
// (isolated to this file) to pin that the clause actually excludes it.
vi.mock('../../src/analysis/newEntity.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../src/analysis/newEntity.js')>();
  return {
    ...original,
    IGNORED_SIGNATURE_KEYS: new Set([...original.IGNORED_SIGNATURE_KEYS, 'ips_alert|ignored sig']),
  };
});

const { allClientMacs, clientDayCounts, clientLastActivitySince, clientMacsSince, eventsForClientMac } = await import(
  '../../src/db/eventQueries.js'
);

describe('client queries exclude ignored signatures', () => {
  function db() {
    const conn = new DatabaseSync(':memory:');
    conn.exec(
      `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, category TEXT, severity INTEGER,
       source_ip TEXT, dest_ip TEXT, dest_port INTEGER, action TEXT, signature TEXT, message TEXT, raw TEXT,
       source_client_name TEXT, source_client_mac TEXT, dest_client_name TEXT, dest_client_mac TEXT)`
    );
    const stmt = conn.prepare(
      `INSERT INTO events (received_at, category, signature, source_client_mac, raw)
       VALUES ('2026-11-25T00:00:00Z', 'ips_alert', ?, ?, 'raw')`
    );
    stmt.run('ignored sig', 'aa:aa:aa:aa:aa:01');
    stmt.run('real sig', 'aa:aa:aa:aa:aa:02');
    return { conn };
  }

  it('drops a client whose only events carry an ignored signature', () => {
    const sink = db();
    expect(allClientMacs(sink)).toEqual(['aa:aa:aa:aa:aa:02']);
    expect(clientMacsSince(sink, '2026-11-01T00:00:00Z')).toEqual(['aa:aa:aa:aa:aa:02']);
    expect(clientDayCounts(sink, '2026-11-01T00:00:00Z').map((r) => r.mac)).toEqual(['aa:aa:aa:aa:aa:02']);
    expect(eventsForClientMac(sink, 'aa:aa:aa:aa:aa:01')).toEqual([]);
    expect(clientLastActivitySince(sink, '2026-11-01T00:00:00Z').map((r) => r.mac)).toEqual(['aa:aa:aa:aa:aa:02']);
  });
});
