import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { openSinkDb, type SinkDb } from '../../src/db/sinkDb.js';
import {
  allClientMacs,
  auditCandidateEvents,
  clientDayCounts,
  clientMacsSince,
  countUnblockedIpsAlerts,
  entityActivitySummary,
  eventsForClientMac,
  eventsForSignature,
  eventsForSourceIp,
  eventsOverTime,
  latestClientNames,
  listEvents,
  severityDistribution,
  signatureEventCounts,
  sourceIpEventCounts,
  topSignatures,
  topSourceIps,
} from '../../src/db/sinkQueries.js';
import { seededSinkDb } from '../helpers.js';

function seededEventsDb(
  rows: {
    received_at: string;
    category: string;
    signature?: string | null;
    source_ip?: string | null;
    action?: string | null;
    message?: string | null;
  }[]
): SinkDb {
  const conn = new DatabaseSync(':memory:');
  conn.exec(
    `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
     category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
     dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
     signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER)`
  );
  const stmt = conn.prepare(
    `INSERT INTO events (received_at, category, signature, source_ip, action, message, raw, parsed)
     VALUES (?, ?, ?, ?, ?, ?, '', 1)`
  );
  for (const r of rows) {
    stmt.run(r.received_at, r.category, r.signature ?? null, r.source_ip ?? null, r.action ?? null, r.message ?? null);
  }
  return { conn };
}

describe('sinkQueries', () => {
  it('listEvents returns rows without throwing against the fixture', () => {
    const db = openSinkDb('tests/fixtures/events.db');
    const events = listEvents(db, { limit: 10 });
    expect(Array.isArray(events)).toBe(true);
  });

  it('listEvents on an empty/:memory: db returns an empty array, not an error', () => {
    const conn = new DatabaseSync(':memory:');
    conn.exec(
      `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
       category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
       dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
       signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER)`
    );
    const db: SinkDb = { conn };
    expect(listEvents(db, {})).toEqual([]);
    expect(eventsOverTime(db, { sinceDays: 7 })).toEqual([]);
    expect(topSignatures(db, { sinceDays: 7, limit: 5 })).toEqual([]);
    expect(topSourceIps(db, { sinceDays: 7, limit: 5 })).toEqual([]);
    expect(severityDistribution(db, { sinceDays: 7 })).toEqual([]);
  });
});

describe('eventsForSourceIp / eventsForSignature action column', () => {
  it('includes the action column in returned rows', () => {
    const db = seededEventsDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
    ]);
    expect(eventsForSourceIp(db, '1.2.3.4')[0].action).toBe('blocked');
    expect(eventsForSignature(db, 'ips_alert', 'ET DROP Foo')[0].action).toBe('blocked');
  });
});

describe('sourceIpEventCounts / signatureEventCounts', () => {
  it('reports total and matching counts for a source IP within a window', () => {
    const db = seededEventsDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
      { received_at: '2026-08-31T02:00:00Z', category: 'ips_alert', signature: 'ET MALWARE Bar', source_ip: '1.2.3.4', action: 'blocked' },
      { received_at: '2026-08-30T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
    ]);
    const counts = sourceIpEventCounts(
      db,
      '1.2.3.4',
      '2026-08-31T00:00:00Z',
      "category = 'ips_alert' AND action = 'blocked' AND signature LIKE ?",
      ['ET DROP%']
    );
    expect(counts.total).toBe(2);
    expect(counts.matching).toBe(1);
  });

  it('reports total and matching counts for a signature within a window', () => {
    const db = seededEventsDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
      { received_at: '2026-08-31T02:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '5.6.7.8', action: 'allowed' },
    ]);
    const counts = signatureEventCounts(
      db,
      'ips_alert',
      'ET DROP Foo',
      '2026-08-31T00:00:00Z',
      "action = 'blocked'"
    );
    expect(counts.total).toBe(2);
    expect(counts.matching).toBe(1);
  });

  it('sourceIpEventCounts respects an optional untilIso upper bound', () => {
    const db = seededEventsDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
      { received_at: '2026-09-05T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
    ]);
    const counts = sourceIpEventCounts(
      db,
      '1.2.3.4',
      '2026-08-31T00:00:00Z',
      "action = 'blocked'",
      [],
      '2026-09-01T00:00:00Z'
    );
    expect(counts.total).toBe(1);
    expect(counts.matching).toBe(1);
  });

  it('signatureEventCounts respects an optional untilIso upper bound', () => {
    const db = seededEventsDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
      { received_at: '2026-09-05T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
    ]);
    const counts = signatureEventCounts(
      db,
      'ips_alert',
      'ET DROP Foo',
      '2026-08-31T00:00:00Z',
      "action = 'blocked'",
      [],
      '2026-09-01T00:00:00Z'
    );
    expect(counts.total).toBe(1);
    expect(counts.matching).toBe(1);
  });
});

describe('auditCandidateEvents', () => {
  it('returns category and message for all events for a source IP in the window, unbounded', () => {
    const db = seededEventsDb(
      Array.from({ length: 25 }, (_, i) => ({
        received_at: `2026-08-31T${String(i).padStart(2, '0')}:00:00Z`,
        category: 'audit',
        source_ip: '1.2.3.4',
        message: `Ian C. accessed UniFi Network using the web. Source IP: 1.2.3.4`,
      }))
    );
    const events = auditCandidateEvents(db, '1.2.3.4', '2026-08-31T00:00:00Z');
    expect(events).toHaveLength(25);
    expect(events[0].category).toBe('audit');
  });

  it('respects an optional untilIso upper bound', () => {
    const db = seededEventsDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'audit', source_ip: '1.2.3.4', message: 'Ian C. accessed UniFi Network using the web. Source IP: 1.2.3.4' },
      { received_at: '2026-09-05T01:00:00Z', category: 'audit', source_ip: '1.2.3.4', message: 'Ian C. accessed UniFi Network using the web. Source IP: 1.2.3.4' },
    ]);
    const events = auditCandidateEvents(db, '1.2.3.4', '2026-08-31T00:00:00Z', '2026-09-01T00:00:00Z');
    expect(events).toHaveLength(1);
  });
});

describe('client queries', () => {
  function clientDb(): SinkDb {
    const conn = new DatabaseSync(':memory:');
    conn.exec(
      `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
       category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
       dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
       signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER,
       source_client_name TEXT, source_client_mac TEXT, dest_client_name TEXT, dest_client_mac TEXT)`
    );
    const stmt = conn.prepare(
      `INSERT INTO events (received_at, category, signature, source_ip, source_client_mac, source_client_name, raw, parsed)
       VALUES (?, ?, 'sig', ?, ?, ?, 'raw-line', 1)`
    );
    // A: client-only ips_alert
    stmt.run('2026-11-01T00:00:00Z', 'ips_alert', null, 'aa:aa:aa:aa:aa:01', 'tranquility');
    // B: same MAC, later, renamed
    stmt.run('2026-11-20T00:00:00Z', 'firewall_block', null, 'aa:aa:aa:aa:aa:01', 'tranq-renamed');
    // C: has an IP -> not client-only
    stmt.run('2026-11-21T00:00:00Z', 'ips_alert', '192.168.1.26', 'aa:aa:aa:aa:aa:02', 'withip');
    // D: not a Security category
    stmt.run('2026-11-21T00:00:00Z', 'internet_and_wan', null, 'aa:aa:aa:aa:aa:03', 'wan');
    // E: name but no MAC
    stmt.run('2026-11-21T00:00:00Z', 'ips_alert', null, null, 'nameonly');
    // F: client-only honeypot
    stmt.run('2026-11-24T00:00:00Z', 'honeypot', null, 'aa:aa:aa:aa:aa:04', null);
    return { conn };
  }

  it('allClientMacs returns distinct MACs of client-only Security events across all history', () => {
    expect(allClientMacs(clientDb()).sort()).toEqual(['aa:aa:aa:aa:aa:01', 'aa:aa:aa:aa:aa:04']);
  });

  it('clientMacsSince restricts to the window', () => {
    const db = clientDb();
    expect(clientMacsSince(db, '2026-11-15T00:00:00Z').sort()).toEqual([
      'aa:aa:aa:aa:aa:01',
      'aa:aa:aa:aa:aa:04',
    ]);
    expect(clientMacsSince(db, '2026-11-22T00:00:00Z')).toEqual(['aa:aa:aa:aa:aa:04']);
  });

  it('clientDayCounts counts distinct active days per MAC', () => {
    expect(clientDayCounts(clientDb(), '2026-10-01T00:00:00Z')).toContainEqual({
      mac: 'aa:aa:aa:aa:aa:01',
      days: 2,
    });
  });

  it('latestClientNames returns the most recent non-null name per MAC', () => {
    const db = clientDb();
    expect(latestClientNames(db, ['aa:aa:aa:aa:aa:01']).get('aa:aa:aa:aa:aa:01')).toBe('tranq-renamed');
    expect(latestClientNames(db, []).size).toBe(0);
  });

  it('latestClientNames picks the newest by received_at, not insertion order', () => {
    const db = clientDb();
    db.conn
      .prepare(
        `INSERT INTO events (received_at, category, source_client_mac, source_client_name, raw, parsed)
         VALUES ('2026-10-01T00:00:00Z', 'ips_alert', 'aa:aa:aa:aa:aa:01', 'ancient-name', 'raw-line', 1)`
      )
      .run();
    expect(latestClientNames(db, ['aa:aa:aa:aa:aa:01']).get('aa:aa:aa:aa:aa:01')).toBe('tranq-renamed');
  });

  it('eventsForClientMac returns client-only events for the MAC, newest first, with client columns', () => {
    const events = eventsForClientMac(clientDb(), 'aa:aa:aa:aa:aa:01');
    expect(events).toHaveLength(2);
    expect(events[0].source_client_name).toBe('tranq-renamed');
  });
});

describe('countUnblockedIpsAlerts / entityActivitySummary', () => {
  const MAC = 'aa:aa:aa:aa:aa:01';
  function activityDb(): SinkDb {
    return seededSinkDb([
      // source IP 198.51.100.4: two unblocked (one NULL action), one blocked, one non-IPS
      { received_at: '2026-11-20T01:00:00Z', category: 'ips_alert', signature: 'ET SCAN A', source_ip: '198.51.100.4', action: 'blocked', dest_ip: '192.168.1.10', dest_port: 22 },
      { received_at: '2026-11-20T02:00:00Z', category: 'ips_alert', signature: 'ET SCAN A', source_ip: '198.51.100.4', action: 'allowed', dest_ip: '192.168.1.10', dest_port: 22 },
      { received_at: '2026-11-20T03:00:00Z', category: 'ips_alert', signature: 'ET SCAN B', source_ip: '198.51.100.4', action: null, dest_ip: '192.168.1.11', dest_port: 443 },
      { received_at: '2026-11-20T04:00:00Z', category: 'firewall_block', signature: 'fw', source_ip: '198.51.100.4', action: 'allowed', dest_ip: '192.168.1.10', dest_port: 22 },
      // before the window
      { received_at: '2026-11-10T00:00:00Z', category: 'ips_alert', signature: 'ET SCAN A', source_ip: '198.51.100.4', action: 'allowed' },
      // another source for the same signature
      { received_at: '2026-11-20T05:00:00Z', category: 'ips_alert', signature: 'ET SCAN A', source_ip: '198.51.100.9', action: 'blocked', dest_ip: '192.168.1.10', dest_port: 22 },
      // client-only events
      { received_at: '2026-11-20T06:00:00Z', category: 'ips_alert', signature: 'ET C2', source_client_mac: MAC, action: 'allowed', dest_ip: '203.0.113.50', dest_port: 8443 },
      { received_at: '2026-11-20T07:00:00Z', category: 'ips_alert', signature: 'ET C2', source_client_mac: MAC, action: 'blocked', dest_ip: '203.0.113.50', dest_port: 8443 },
      // same MAC but with an IP: not client-only
      { received_at: '2026-11-20T08:00:00Z', category: 'ips_alert', signature: 'ET C2', source_ip: '192.168.1.26', source_client_mac: MAC, action: 'allowed' },
    ]);
  }
  const SINCE = '2026-11-15T00:00:00Z';

  it('counts unblocked IPS alerts per entity type, NULL action counting as unblocked', () => {
    const db = activityDb();
    expect(countUnblockedIpsAlerts(db, 'source_ip', '198.51.100.4', SINCE)).toBe(2);
    expect(countUnblockedIpsAlerts(db, 'signature', 'ips_alert|ET SCAN A', SINCE)).toBe(1);
    expect(countUnblockedIpsAlerts(db, 'signature', 'firewall_block|fw', SINCE)).toBe(0);
    expect(countUnblockedIpsAlerts(db, 'client', MAC, SINCE)).toBe(1);
    expect(countUnblockedIpsAlerts(db, 'source_ip', '198.51.100.4', '2026-11-01T00:00:00Z')).toBe(3);
  });

  it('summarises a source IP: actions, ports, dest IPs and signatures as counterparts', () => {
    const s = entityActivitySummary(activityDb(), 'source_ip', '198.51.100.4', SINCE);
    expect(s.total).toBe(4);
    expect(s.by_action).toEqual({ blocked: 1, allowed: 2, unknown: 1 });
    expect(s.top_dest_ports).toEqual([
      { value: 22, count: 3 },
      { value: 443, count: 1 },
    ]);
    expect(s.top_dest_ips[0]).toEqual({ value: '192.168.1.10', count: 3 });
    expect(s.top_counterparts).toEqual([
      { value: 'ET SCAN A', count: 2 },
      { value: 'ET SCAN B', count: 1 },
      { value: 'fw', count: 1 },
    ]);
  });

  it('summarises a signature with source IPs as counterparts and honours untilIso', () => {
    const db = activityDb();
    const s = entityActivitySummary(db, 'signature', 'ips_alert|ET SCAN A', SINCE);
    expect(s.total).toBe(3);
    expect(s.top_counterparts).toEqual([
      { value: '198.51.100.4', count: 2 },
      { value: '198.51.100.9', count: 1 },
    ]);
    const bounded = entityActivitySummary(db, 'signature', 'ips_alert|ET SCAN A', SINCE, '2026-11-20T01:30:00Z');
    expect(bounded.total).toBe(1);
  });

  it('summarises client-only events for a MAC', () => {
    const s = entityActivitySummary(activityDb(), 'client', MAC, SINCE);
    expect(s.total).toBe(2);
    expect(s.top_dest_ports).toEqual([{ value: 8443, count: 2 }]);
    expect(s.top_counterparts).toEqual([{ value: 'ET C2', count: 2 }]);
  });

  it('caps each top list at 5', () => {
    const db = seededSinkDb(
      Array.from({ length: 8 }, (_, i) => ({
        received_at: '2026-11-20T00:00:00Z',
        category: 'ips_alert',
        signature: `sig-${i}`,
        source_ip: '198.51.100.4',
        dest_port: 1000 + i,
        dest_ip: `192.168.1.${i + 1}`,
      }))
    );
    const s = entityActivitySummary(db, 'source_ip', '198.51.100.4', SINCE);
    expect(s.top_dest_ports).toHaveLength(5);
    expect(s.top_dest_ips).toHaveLength(5);
    expect(s.top_counterparts).toHaveLength(5);
  });

  it('client variants throw on a pre-v1.0.3 sink (no client columns); IP/signature variants do not', () => {
    const old = seededEventsDb([
      { received_at: '2026-11-20T00:00:00Z', category: 'ips_alert', signature: 'x', source_ip: '198.51.100.4', action: 'allowed' },
    ]);
    expect(() => countUnblockedIpsAlerts(old, 'client', MAC, SINCE)).toThrow();
    expect(() => entityActivitySummary(old, 'client', MAC, SINCE)).toThrow();
    expect(countUnblockedIpsAlerts(old, 'source_ip', '198.51.100.4', SINCE)).toBe(1);
    expect(entityActivitySummary(old, 'source_ip', '198.51.100.4', SINCE).total).toBe(1);
  });
});
