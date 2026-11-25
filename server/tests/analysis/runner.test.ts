import { describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { openLensDb, type LensDb } from '../../src/db/lensDb.js';
import {
  getFinding,
  listFindings,
  markSeenSignature,
  markSeenSourceIp,
  updateFindingState,
  upsertFinding,
} from '../../src/db/findingsStore.js';
import {
  cancelPendingRequests,
  createAnalysisRequest,
  getAnalysisRequest,
  getAnalysisRequestsForFinding,
  getPendingRequestForFinding,
} from '../../src/db/analysisRequestsStore.js';
import { listHistory } from '../../src/db/findingHistoryStore.js';
import { applyTrigger, type ClosedBy, type Finding } from '../../src/analysis/findings.js';
import {
  runDailyAnomalyCheck,
  runDailyRecheck,
  runHourlyChecks,
  runRuleTriageBackfill,
} from '../../src/analysis/runner.js';
import { runnerDeps, seededSinkDb } from '../helpers.js';

// Pre-sink-v1.0.3 schema: no client columns.
function legacySinkDb(
  rows: {
    received_at: string;
    category: string;
    signature: string | null;
    source_ip: string | null;
  }[]
) {
  const conn = new DatabaseSync(':memory:');
  conn.exec(
    `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, category TEXT,
     signature TEXT, source_ip TEXT, severity INTEGER, action TEXT, message TEXT,
     dest_ip TEXT, dest_port INTEGER)`
  );
  const stmt = conn.prepare(
    'INSERT INTO events (received_at, category, signature, source_ip) VALUES (?, ?, ?, ?)'
  );
  for (const r of rows) stmt.run(r.received_at, r.category, r.signature, r.source_ip);
  return { conn };
}

const HOUR = 3600_000;

const byKey = (lensDb: LensDb, key: string) =>
  listFindings(lensDb, { view: 'all' }).find((f) => f.entity_key === key);

const kinds = (lensDb: LensDb, f: Finding | undefined) =>
  listHistory(lensDb, f?.id as number).map((h) => h.kind);

// Puts a finding into `closed` the way a decision would (pending request gone,
// last_triaged_at stamped), without going through the pipeline under test.
function closeAs(lensDb: LensDb, f: Finding, by: ClosedBy, atIso: string): Finding {
  cancelPendingRequests(lensDb, f.id as number);
  return updateFindingState(lensDb, f.id as number, {
    status: 'closed',
    closed_by: by,
    closed_reason: 'test close',
    closed_at: atIso,
    last_triaged_at: atIso,
  }) as Finding;
}

// Asserts the finding was closed by a rule with exactly one rule-sourced,
// answered analysis row (and nothing pending).
function expectRuleClosed(lensDb: LensDb, f: Finding | undefined) {
  expect(f).toBeDefined();
  expect(f?.status).toBe('closed');
  expect(f?.closed_by).toBe('rule');
  const requests = getAnalysisRequestsForFinding(lensDb, f?.id as number);
  expect(requests).toHaveLength(1);
  expect(requests[0].source).toBe('rule');
  expect(requests[0].status).toBe('answered');
  expect(requests[0].risk_level).toBe('low');
  return requests[0];
}

// Asserts the finding is waiting on AI: triaging with exactly one pending,
// AI-sourced request and no rule analysis.
function expectQueued(lensDb: LensDb, f: Finding | undefined) {
  expect(f).toBeDefined();
  expect(f?.status).toBe('triaging');
  const requests = getAnalysisRequestsForFinding(lensDb, f?.id as number);
  expect(requests).toHaveLength(1);
  expect(requests[0].status).toBe('pending');
  expect(requests[0].source).toBe('ai');
  return requests[0];
}

describe('runHourlyChecks', () => {
  it('flags a brand-new signature and a brand-new source IP', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.5' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    const types = listFindings(lensDb, { view: 'all' }).flatMap((f) => f.triggers.map((t) => t.type));
    expect(types).toContain('new_signature');
    expect(types).toContain('new_source_ip');
  });

  it('flags an internal-source event', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '10.0.30.5' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb, { lanCidrs: ['10.0.0.0/8'] }), now);

    expect(byKey(lensDb, '10.0.30.5')?.triggers.some((t) => t.type === 'internal_source')).toBe(true);
  });

  it('flags a repeat offender once it crosses the distinct-day threshold', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const days = ['2026-08-29', '2026-08-30', '2026-08-31'];
    const sinkDb = seededSinkDb(
      days.map((d) => ({ received_at: `${d}T01:00:00Z`, category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.9' }))
    );
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    expect(byKey(lensDb, '203.0.113.9')?.triggers.some((t) => t.type === 'repeat_offender' && t.active)).toBe(true);
  });

  it('never raises a finding for an ignored signature (Protect doorbell ring)', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([{ received_at: now.toISOString(), category: 'siteactivity', signature: '2154' }]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    expect(listFindings(lensDb, { view: 'all' })).toEqual([]);
  });

  it('queues a new finding no rule explains, with empty context', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.5' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    for (const key of ['203.0.113.5', 'ips_alert|ET SCAN Nmap']) {
      const f = byKey(lensDb, key);
      const req = expectQueued(lensDb, f);
      expect(req.context).toBe('{}');
      expect(req.is_recheck).toBe(0);
      expect(kinds(lensDb, f)).toEqual(['created', 'queued']);
    }
  });

  it('routes a newly created repeat-offender finding through rules over the 14-day window', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const lensDb = openLensDb(':memory:');
    // Known IP and signature, and every event older than 24h: only the
    // repeat-offender loop creates this finding, and only a 14-day rule
    // window can see the events that back it.
    markSeenSourceIp(lensDb, '203.0.113.9', '2026-08-01T00:00:00Z');
    markSeenSignature(lensDb, 'ips_alert', 'ET DROP Foo', '2026-08-01T00:00:00Z');
    const sinkDb = seededSinkDb(
      ['2026-08-21', '2026-08-25', '2026-08-29'].map((d) => ({
        received_at: `${d}T01:00:00Z`,
        category: 'ips_alert',
        signature: 'ET DROP Foo',
        source_ip: '203.0.113.9',
        action: 'blocked',
      }))
    );
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    const f = byKey(lensDb, '203.0.113.9');
    expect(f?.triggers.map((t) => t.type)).toEqual(['repeat_offender']);
    expectRuleClosed(lensDb, f);
    expect(kinds(lensDb, f)).toEqual(['created', 'rule_closed']);
  });

  it('does not re-route an existing triaging finding that gains another trigger', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.9' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    const insert = sinkDb.conn.prepare(
      "INSERT INTO events (received_at, category, signature, source_ip, raw) VALUES (?, 'ips_alert', 'ET SCAN Nmap', '203.0.113.9', 'raw')"
    );
    insert.run('2026-09-01T01:00:00Z');
    insert.run('2026-09-02T01:00:00Z');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), new Date('2026-09-02T12:00:00Z'));

    const f = byKey(lensDb, '203.0.113.9');
    expect(f?.triggers.some((t) => t.type === 'repeat_offender' && t.active)).toBe(true);
    expectQueued(lensDb, f);
    expect(kinds(lensDb, f)).toEqual(['created', 'queued', 'trigger_added']);
  });

  it('updates last_activity_at to the entity max received_at seen in the window', () => {
    const t0 = '2026-08-31T09:00:00.000Z';
    const lensDb = openLensDb(':memory:');
    upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', t0, 'source_ip', '203.0.113.5'));
    upsertFinding(lensDb, applyTrigger(null, 'new_signature', t0, 'signature', 'ips_alert|ET SCAN Nmap'));
    markSeenSourceIp(lensDb, '203.0.113.5', t0);
    markSeenSignature(lensDb, 'ips_alert', 'ET SCAN Nmap', t0);
    const sinkDb = seededSinkDb([
      { received_at: '2026-08-31T10:00:00.000Z', category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.5' },
      { received_at: '2026-08-31T11:00:00.000Z', category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.5' },
      // A different source on the same signature moves the signature's activity only.
      { received_at: '2026-08-31T11:30:00.000Z', category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.6' },
    ]);
    runHourlyChecks(runnerDeps(sinkDb, lensDb), new Date('2026-08-31T12:00:00Z'));

    expect(getFinding(lensDb, 'source_ip', '203.0.113.5')?.last_activity_at).toBe('2026-08-31T11:00:00.000Z');
    expect(getFinding(lensDb, 'signature', 'ips_alert|ET SCAN Nmap')?.last_activity_at).toBe(
      '2026-08-31T11:30:00.000Z'
    );
  });

  it('a lifted repeat_offender trigger does not change status', () => {
    const lensDb = openLensDb(':memory:');
    const t0 = '2026-08-31T12:00:00.000Z';
    const f = upsertFinding(lensDb, applyTrigger(null, 'repeat_offender', t0, 'source_ip', '203.0.113.9'));
    closeAs(lensDb, f, 'ai', t0);
    runHourlyChecks(runnerDeps(seededSinkDb([]), lensDb), new Date('2026-09-30T12:00:00Z'));

    const after = byKey(lensDb, '203.0.113.9');
    expect(after?.triggers.find((t) => t.type === 'repeat_offender')?.active).toBe(false);
    expect(after?.status).toBe('closed');
    expect(after?.closed_by).toBe('ai');
  });
});

describe('runDailyAnomalyCheck', () => {
  // 13 quiet days at count 1, then a spike day at count 50.
  function spikeRows(category: string, signature: string, extra: Record<string, unknown> = {}) {
    const rows = [];
    for (let i = 13; i >= 1; i--) {
      const day = new Date(Date.UTC(2026, 7, 31 - i)).toISOString().slice(0, 10);
      rows.push({ received_at: `${day}T01:00:00Z`, category, signature, source_ip: '203.0.113.1', ...extra });
    }
    for (let i = 0; i < 50; i++) {
      rows.push({ received_at: '2026-08-30T01:00:00Z', category, signature, source_ip: '203.0.113.1', ...extra });
    }
    return rows;
  }

  it('flags a signature whose count is far above its 14-day baseline, and queues it', () => {
    const sinkDb = seededSinkDb(spikeRows('ips_alert', 'ET TROJAN Foo'));
    const lensDb = openLensDb(':memory:');
    runDailyAnomalyCheck(runnerDeps(sinkDb, lensDb), '2026-08-30', new Date('2026-08-31T00:10:00Z'));

    const f = byKey(lensDb, 'ips_alert|ET TROJAN Foo');
    expect(f?.triggers.some((t) => t.type === 'anomaly' && t.active)).toBe(true);
    expect(f?.first_seen).toBe('2026-08-31T00:10:00.000Z');
    expectQueued(lensDb, f);
  });

  it('routes a newly created anomaly finding through rules over the anomaly day', () => {
    const sinkDb = seededSinkDb([
      ...spikeRows('ips_alert', 'ET DROP Spike', { action: 'blocked' }),
      // The day after the anomaly day: outside [day, day+1), so a non-matching
      // event here must not spoil the rule's completeness check.
      { received_at: '2026-08-31T00:05:00Z', category: 'ips_alert', signature: 'ET DROP Spike', source_ip: '203.0.113.1', action: 'allowed' },
    ]);
    const lensDb = openLensDb(':memory:');
    runDailyAnomalyCheck(runnerDeps(sinkDb, lensDb), '2026-08-30', new Date('2026-08-31T00:10:00Z'));

    const f = byKey(lensDb, 'ips_alert|ET DROP Spike');
    expect(f?.triggers.map((t) => t.type)).toEqual(['anomaly']);
    expectRuleClosed(lensDb, f);
  });

  it('never flags an anomaly for an ignored signature (Protect doorbell ring)', () => {
    const sinkDb = seededSinkDb(spikeRows('siteactivity', '2154', { source_ip: null }));
    const lensDb = openLensDb(':memory:');
    runDailyAnomalyCheck(runnerDeps(sinkDb, lensDb), '2026-08-30');

    expect(listFindings(lensDb, { view: 'all' })).toEqual([]);
    const baselineRows = lensDb.conn.prepare('SELECT COUNT(*) as n FROM baselines').get() as { n: number };
    expect(baselineRows.n).toBe(0);
  });
});

describe('rule-based triage at creation', () => {
  const now = new Date('2026-08-31T12:00:00Z');
  const at = now.toISOString();

  it('rule-closes a reputation-blocklist new_source_ip finding with a rule-sourced analysis', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'ips_alert', signature: 'ET DROP Dshield Block Listed Source group 1', source_ip: '203.0.113.5', action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    const f = byKey(lensDb, '203.0.113.5');
    expectRuleClosed(lensDb, f);
    expect(kinds(lensDb, f)).toEqual(['created', 'rule_closed']);
    expectRuleClosed(lensDb, byKey(lensDb, 'ips_alert|ET DROP Dshield Block Listed Source group 1'));
  });

  it('queues a signature outside the safe-prefix list', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'ips_alert', signature: 'ET MALWARE Backdoor family PCRat/Gh0st CnC traffic', source_ip: '203.0.113.6', action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    expectQueued(lensDb, byKey(lensDb, '203.0.113.6'));
  });

  it('rule-closes a trusted admin audit-login new_source_ip finding', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'audit', source_ip: '192.168.1.134', message: 'Ian C. accessed UniFi Network using the web. Source IP: 192.168.1.134' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb, { trustedAdminNames: ['Ian C.'] }), now);

    expectRuleClosed(lensDb, byKey(lensDb, '192.168.1.134'));
  });

  it('queues an untrusted admin audit login for AI', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'audit', source_ip: '192.168.1.200', message: 'Mallory accessed UniFi Network using the web. Source IP: 192.168.1.200' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb, { trustedAdminNames: ['Ian C.'] }), now);

    expectQueued(lensDb, byKey(lensDb, '192.168.1.200'));
  });

  it('rule-closes an operational-noise new_source_ip finding', () => {
    const sinkDb = seededSinkDb([{ received_at: at, category: 'internet_and_wan', source_ip: '192.168.1.1' }]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    expectRuleClosed(lensDb, byKey(lensDb, '192.168.1.1'));
  });

  it('rule-closes an operational-noise new_signature finding (device telemetry event code)', () => {
    const sinkDb = seededSinkDb([{ received_at: at, category: 'unifi_devices', signature: '512', source_ip: '192.168.1.43' }]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    expectRuleClosed(lensDb, byKey(lensDb, 'unifi_devices|512'));
  });

  it('rule-closes an operational-noise new_signature finding (software update event code)', () => {
    const sinkDb = seededSinkDb([{ received_at: at, category: 'software_updates', signature: '510', source_ip: '192.168.1.207' }]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    expectRuleClosed(lensDb, byKey(lensDb, 'software_updates|510'));
  });

  it('rule-closes a low-signal-category new_signature finding (system bookkeeping event)', () => {
    const sinkDb = seededSinkDb([{ received_at: at, category: 'system', signature: '100', source_ip: '192.168.1.1' }]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    expectRuleClosed(lensDb, byKey(lensDb, 'system|100'));
  });

  it('queues an untrusted-name audit-category new_signature finding for AI', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'audit', signature: '200', source_ip: '192.168.1.200', message: 'Mallory accessed UniFi Network using the web. Source IP: 192.168.1.200' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb, { trustedAdminNames: ['Ian C.'] }), now);

    expectQueued(lensDb, byKey(lensDb, 'audit|200'));
  });

  it('rule-closes an internal-source finding whose events are all operational noise', () => {
    const sinkDb = seededSinkDb([{ received_at: at, category: 'unifi_devices', signature: '514', source_ip: '10.0.30.43' }]);
    const lensDb = openLensDb(':memory:');
    // Pre-seed the signature and source IP as already-known so only the
    // internal-source loop (not new-signature/new-source-ip) processes this
    // event — isolating the case a known LAN device generates ordinary
    // device telemetry, which is the actual "device switching APs" scenario.
    markSeenSignature(lensDb, 'unifi_devices', '514', at);
    markSeenSourceIp(lensDb, '10.0.30.43', at);
    runHourlyChecks(runnerDeps(sinkDb, lensDb, { lanCidrs: ['10.0.0.0/8'] }), now);

    const f = byKey(lensDb, '10.0.30.43');
    expect(f?.triggers.some((t) => t.type === 'internal_source' && t.active)).toBe(true);
    expectRuleClosed(lensDb, f);
  });

  it('same-pass reopen: a rule-closed source IP that also trips internal-source ends the pass triaging with a pending request', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'ips_alert', signature: 'ET DROP Dshield Block Listed Source group 1', source_ip: '10.0.30.5', action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb, { lanCidrs: ['10.0.0.0/8'] }), now);

    const f = listFindings(lensDb, { view: 'all' }).find((x) => x.entity_key === '10.0.30.5')!;
    expect(f.status).toBe('triaging');
    expect(f.closed_by).toBeNull();
    expect(f.triggers.some((t) => t.type === 'internal_source' && t.active)).toBe(true);
    expect(f.triggers.some((t) => t.type === 'new_source_ip' && t.active)).toBe(true);
    expect(getPendingRequestForFinding(lensDb, f.id!)).not.toBeNull();
    expect(listHistory(lensDb, f.id!).map((h) => h.kind)).toEqual(['created', 'rule_closed', 'trigger_added', 'queued']);
    const ruleRequests = getAnalysisRequestsForFinding(lensDb, f.id!).filter((r) => r.source === 'rule');
    expect(ruleRequests).toHaveLength(1);
  });

  const tranquility = {
    '192.168.1.26': {
      label: 'tranquility',
      services: [{ port: 50300, name: 'slskd', description: 'Soulseek P2P listen port' }],
    },
  };

  it('rule-closes a new_signature finding whose events all match a known homelab service egress port', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'ips_alert', signature: 'ET MALWARE Backdoor family PCRat/Gh0st CnC traffic', source_ip: '192.168.1.26', dest_ip: '198.51.100.20', dest_port: 50300, action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb, { homelabServices: tranquility }), now);

    const req = expectRuleClosed(lensDb, byKey(lensDb, 'ips_alert|ET MALWARE Backdoor family PCRat/Gh0st CnC traffic'));
    expect(req.recommendation).toContain('slskd');
  });

  it('queues via no homelab-service match when an event falls outside the known port', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'ips_alert', signature: 'ET MALWARE Backdoor family PCRat/Gh0st CnC traffic', source_ip: '192.168.1.26', dest_ip: '198.51.100.20', dest_port: 50300, action: 'blocked' },
      { received_at: at, category: 'ips_alert', signature: 'ET MALWARE Backdoor family PCRat/Gh0st CnC traffic', source_ip: '192.168.1.26', dest_ip: '198.51.100.9', dest_port: 4444, action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb, { homelabServices: tranquility }), now);

    expectQueued(lensDb, byKey(lensDb, 'ips_alert|ET MALWARE Backdoor family PCRat/Gh0st CnC traffic'));
  });

  it('rule-closes a new_source_ip finding whose only event is a blocked hit against a wanExposed host', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'ips_alert', signature: 'ET MALWARE VenomRAT CnC Server Keepalive', source_ip: '203.0.113.16', dest_ip: '192.168.1.26', dest_port: 58370, action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      runnerDeps(sinkDb, lensDb, {
        homelabServices: { '192.168.1.26': { label: 'tranquility', wanExposed: true, services: [{ port: 50300, name: 'slskd' }] } },
      }),
      now
    );

    const req = expectRuleClosed(lensDb, byKey(lensDb, '203.0.113.16'));
    expect(req.recommendation).toContain('tranquility');
  });

  it('queues when the exposed-host target is not marked wanExposed', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'ips_alert', signature: 'ET MALWARE VenomRAT CnC Server Keepalive', source_ip: '203.0.113.16', dest_ip: '192.168.1.26', dest_port: 58370, action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      runnerDeps(sinkDb, lensDb, { homelabServices: { '192.168.1.26': { label: 'tranquility', services: [] } } }),
      now
    );

    expectQueued(lensDb, byKey(lensDb, '203.0.113.16'));
  });

  it('queues when an event misses the wanExposed host', () => {
    const sinkDb = seededSinkDb([
      { received_at: at, category: 'ips_alert', signature: 'ET MALWARE VenomRAT CnC Server Keepalive', source_ip: '203.0.113.16', dest_ip: '192.168.1.26', dest_port: 58370, action: 'blocked' },
      { received_at: at, category: 'ips_alert', signature: 'ET MALWARE VenomRAT CnC Server Keepalive', source_ip: '203.0.113.16', dest_ip: '10.0.0.9', dest_port: 22, action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      runnerDeps(sinkDb, lensDb, { homelabServices: { '192.168.1.26': { label: 'tranquility', wanExposed: true, services: [] } } }),
      now
    );

    expectQueued(lensDb, byKey(lensDb, '203.0.113.16'));
  });
});

describe('runDailyRecheck', () => {
  const t0 = '2026-08-20T12:00:00.000Z';
  const now = new Date('2026-08-22T12:00:00Z');

  // A closed source-IP finding (decided at t0) with new activity at `activityAt`
  // whose events are the given rows.
  function closedWithActivity(
    rows: Parameters<typeof seededSinkDb>[0],
    opts: { by?: ClosedBy; internal?: boolean } = {}
  ) {
    const lensDb = openLensDb(':memory:');
    let f = upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', t0, 'source_ip', '203.0.113.5'));
    if (opts.internal) f = upsertFinding(lensDb, applyTrigger(f, 'internal_source', t0, 'source_ip', '203.0.113.5'));
    closeAs(lensDb, f, opts.by ?? 'rule', t0);
    markSeenSourceIp(lensDb, '203.0.113.5', t0);
    for (const r of rows) if (r.signature) markSeenSignature(lensDb, r.category, r.signature, t0);
    const sinkDb = seededSinkDb(rows);
    // The hourly pass is what moves last_activity_at forward.
    runHourlyChecks(runnerDeps(sinkDb, lensDb), new Date(now.getTime() - HOUR));
    return { lensDb, sinkDb, deps: runnerDeps(sinkDb, lensDb) };
  }

  const blockedDrop = { received_at: '2026-08-22T10:00:00.000Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '203.0.113.5', action: 'blocked' };
  const scan = { received_at: '2026-08-22T10:00:00.000Z', category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.5' };

  it('keeps a closed finding closed when a rule still explains the new activity (no analysis row)', () => {
    const { lensDb, deps } = closedWithActivity([blockedDrop]);
    expect(runDailyRecheck(deps, now)).toEqual({ checked: 1, stillClosed: 1, requeued: 0 });

    const f = byKey(lensDb, '203.0.113.5');
    expect(f?.status).toBe('closed');
    expect(f?.last_triaged_at).toBe(now.toISOString());
    expect(getAnalysisRequestsForFinding(lensDb, f?.id as number)).toEqual([]);
    expect(kinds(lensDb, f)).toEqual(['recheck_rule_still_closed']);
  });

  it('requeues a closed finding with unexplained new activity as a recheck', () => {
    const { lensDb, deps } = closedWithActivity([scan], { by: 'ai' });
    expect(runDailyRecheck(deps, now)).toEqual({ checked: 1, stillClosed: 0, requeued: 1 });

    const f = byKey(lensDb, '203.0.113.5');
    expect(f?.status).toBe('triaging');
    expect(f?.closed_by).toBeNull();
    expect(f?.reopen_count).toBe(1);
    const pending = getPendingRequestForFinding(lensDb, f?.id as number);
    expect(pending?.is_recheck).toBe(1);
    expect(kinds(lensDb, f)).toEqual(['recheck_queued']);
  });

  it('runs at most once per 24h: a second run right after does nothing', () => {
    const { deps } = closedWithActivity([blockedDrop]);
    expect(runDailyRecheck(deps, now)).toEqual({ checked: 1, stillClosed: 1, requeued: 0 });
    expect(runDailyRecheck(deps, new Date(now.getTime() + 60_000))).toEqual({ checked: 0, stillClosed: 0, requeued: 0 });
  });

  it('skips a closed finding with no activity since its last decision', () => {
    const { deps } = closedWithActivity([]);
    expect(runDailyRecheck(deps, now)).toEqual({ checked: 0, stillClosed: 0, requeued: 0 });
  });

  it('applies the internal-source restriction on recheck', () => {
    const { lensDb, deps } = closedWithActivity([blockedDrop], { by: 'ai', internal: true });
    expect(runDailyRecheck(deps, now)).toEqual({ checked: 1, stillClosed: 0, requeued: 1 });
    expect(byKey(lensDb, '203.0.113.5')?.status).toBe('triaging');
  });

  it('ignores attention and triaging findings', () => {
    const lensDb = openLensDb(':memory:');
    const a = upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', t0, 'source_ip', '203.0.113.5'));
    updateFindingState(lensDb, a.id as number, { status: 'attention', last_triaged_at: t0 });
    const tr = upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', t0, 'source_ip', '203.0.113.6'));
    createAnalysisRequest(lensDb, tr.id as number, t0);
    markSeenSourceIp(lensDb, '203.0.113.5', t0);
    markSeenSourceIp(lensDb, '203.0.113.6', t0);
    markSeenSignature(lensDb, 'ips_alert', 'ET DROP Foo', t0);
    const sinkDb = seededSinkDb([blockedDrop, { ...blockedDrop, source_ip: '203.0.113.6' }]);
    runHourlyChecks(runnerDeps(sinkDb, lensDb), new Date(now.getTime() - HOUR));

    expect(runDailyRecheck(runnerDeps(sinkDb, lensDb), now)).toEqual({ checked: 0, stillClosed: 0, requeued: 0 });
    expect(byKey(lensDb, '203.0.113.5')?.status).toBe('attention');
    expect(byKey(lensDb, '203.0.113.6')?.status).toBe('triaging');
  });

  it('requeues a closed client finding with new activity (no rule can keep it closed)', () => {
    const MAC = 'aa:aa:aa:aa:aa:01';
    const lensDb = openLensDb(':memory:');
    const sinkDb = seededSinkDb([
      { received_at: t0, category: 'ips_alert', signature: 'ET MALWARE VenomRAT', source_client_mac: MAC },
    ]);
    runHourlyChecks(runnerDeps(sinkDb, lensDb), new Date(t0));
    closeAs(lensDb, byKey(lensDb, MAC) as Finding, 'ai', t0);
    sinkDb.conn
      .prepare(
        "INSERT INTO events (received_at, category, signature, source_client_mac, raw) VALUES (?, 'ips_alert', 'ET MALWARE VenomRAT', ?, 'raw')"
      )
      .run('2026-08-22T10:00:00.000Z', MAC);
    runHourlyChecks(runnerDeps(sinkDb, lensDb), new Date(now.getTime() - HOUR));
    expect(byKey(lensDb, MAC)?.last_activity_at).toBe('2026-08-22T10:00:00.000Z');

    expect(runDailyRecheck(runnerDeps(sinkDb, lensDb), now)).toEqual({ checked: 1, stillClosed: 0, requeued: 1 });
    const f = byKey(lensDb, MAC);
    expect(f?.status).toBe('triaging');
    expect(getPendingRequestForFinding(lensDb, f?.id as number)?.is_recheck).toBe(1);
  });
});

describe('runRuleTriageBackfill', () => {
  const firstSeen = '2026-08-20T12:00:00Z';

  it('closes an existing triaging finding whose window-scoped events all match a rule, and reports counts', () => {
    const sinkDb = seededSinkDb([
      // Before first_seen, inside [first_seen - 24h, first_seen) — first_seen is stamped
      // with the detection *run* time, at the end of the trailing window, not the start.
      { received_at: '2026-08-20T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '203.0.113.5', action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', firstSeen, 'source_ip', '203.0.113.5'));

    const result = runRuleTriageBackfill(runnerDeps(sinkDb, lensDb));

    expect(result.checked).toBe(1);
    expect(result.closed).toBe(1);
    expect(result.byRule.reputation_blocklist).toBe(1);
    expectRuleClosed(lensDb, byKey(lensDb, '203.0.113.5'));
  });

  it('closes a pre-existing finding for an ignored signature, even with no events left in its window', () => {
    const lensDb = openLensDb(':memory:');
    upsertFinding(lensDb, applyTrigger(null, 'new_signature', firstSeen, 'signature', 'siteactivity|2154'));

    const result = runRuleTriageBackfill(runnerDeps(seededSinkDb([]), lensDb));

    expect(result.closed).toBe(1);
    expect(result.byRule.ignored_signature).toBe(1);
    expectRuleClosed(lensDb, byKey(lensDb, 'siteactivity|2154'));
  });

  it('skips closed and attention findings', () => {
    const sinkDb = seededSinkDb([
      { received_at: '2026-08-20T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '203.0.113.98', action: 'blocked' },
      { received_at: '2026-08-20T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '203.0.113.99', action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    const closed = upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', firstSeen, 'source_ip', '203.0.113.98'));
    closeAs(lensDb, closed, 'human', firstSeen);
    const attention = upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', firstSeen, 'source_ip', '203.0.113.99'));
    updateFindingState(lensDb, attention.id as number, { status: 'attention' });

    const result = runRuleTriageBackfill(runnerDeps(sinkDb, lensDb));

    expect(result.checked).toBe(0);
    expect(result.closed).toBe(0);
    expect(byKey(lensDb, '203.0.113.98')?.closed_by).toBe('human');
    expect(byKey(lensDb, '203.0.113.99')?.status).toBe('attention');
  });

  it('backfill only considers triaging findings and cancels the pending request on close', () => {
    const sinkDb = seededSinkDb([
      { received_at: '2026-08-20T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '203.0.113.7', action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    const f = upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', firstSeen, 'source_ip', '203.0.113.7'));
    const pending = createAnalysisRequest(lensDb, f.id as number, '2026-08-20T13:00:00Z');

    const result = runRuleTriageBackfill(runnerDeps(sinkDb, lensDb), new Date('2026-08-25T00:00:00Z'));

    expect(result).toMatchObject({ checked: 1, closed: 1 });
    expect(getAnalysisRequest(lensDb, pending.id)?.status).toBe('cancelled');
    const after = byKey(lensDb, '203.0.113.7');
    expect(after?.status).toBe('closed');
    expect(after?.closed_at).toBe('2026-08-25T00:00:00.000Z');
    expect(getPendingRequestForFinding(lensDb, f.id as number)).toBeNull();
    expect(kinds(lensDb, after)).toEqual(['request_cancelled', 'rule_closed']);
  });

  it('anchors the completeness window to [first_seen - 24h, first_seen), not to now', () => {
    const sinkDb = seededSinkDb([
      { received_at: '2026-08-20T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '203.0.113.9', action: 'blocked' },
      // Outside the [first_seen - 24h, first_seen) window (it's after first_seen) and
      // non-matching — must not count toward `total`, or completeness would wrongly fail.
      { received_at: '2026-09-01T00:00:00Z', category: 'ips_alert', signature: 'ET MALWARE Bar', source_ip: '203.0.113.9', action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', firstSeen, 'source_ip', '203.0.113.9'));

    expect(runRuleTriageBackfill(runnerDeps(sinkDb, lensDb)).closed).toBe(1);
  });
});

describe('client findings', () => {
  const MAC = 'aa:aa:aa:aa:aa:01';
  const now = new Date('2026-11-25T12:00:00Z');
  const clientRow = (received_at: string, extra: Record<string, unknown> = {}) => ({
    received_at,
    category: 'ips_alert',
    signature: 'ET MALWARE VenomRAT',
    source_ip: null,
    source_client_mac: MAC,
    source_client_name: 'tranquility',
    ...extra,
  });
  const clientFindings = (lensDb: LensDb) =>
    listFindings(lensDb, { view: 'all' }).filter((f) => f.entity_type === 'client');
  const insertClientEvent = (sinkDb: ReturnType<typeof seededSinkDb>, at: string) =>
    sinkDb.conn
      .prepare(
        "INSERT INTO events (received_at, category, signature, source_ip, source_client_mac, raw) VALUES (?, 'ips_alert', 'ET MALWARE VenomRAT', NULL, ?, 'raw')"
      )
      .run(at, MAC);

  it('raises a client finding for a client-only Security alert', () => {
    const sinkDb = seededSinkDb([clientRow(now.toISOString())]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    const [finding] = clientFindings(lensDb);
    expect(finding.entity_key).toBe(MAC);
    expect(finding.triggers.map((t) => t.type).sort()).toEqual(['internal_source', 'new_client']);
    expect(finding.severity_score).toBe(4);
    expect(finding.status).toBe('triaging');
  });

  it('a new client finding gets new_client + internal_source and is queued exactly once', () => {
    const sinkDb = seededSinkDb([clientRow(now.toISOString())]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    const [f] = clientFindings(lensDb);
    expectQueued(lensDb, f);
    expect(kinds(lensDb, f)).toEqual(['created', 'trigger_added', 'queued']);
  });

  it('seeds client findings from all sink history on first run', () => {
    const sinkDb = seededSinkDb([clientRow('2026-09-01T00:00:00Z')]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    expect(clientFindings(lensDb).map((f) => f.entity_key)).toEqual([MAC]);
  });

  it('does not re-add new_client for an already-seen client', () => {
    const sinkDb = seededSinkDb([clientRow(now.toISOString())]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);
    runHourlyChecks(runnerDeps(sinkDb, lensDb), new Date(now.getTime() + HOUR));

    const [finding] = clientFindings(lensDb);
    expect(finding.triggers.filter((t) => t.type === 'new_client')).toHaveLength(1);
    expectQueued(lensDb, finding);
  });

  it('updates a client finding last_activity_at from client-only events', () => {
    const sinkDb = seededSinkDb([clientRow(now.toISOString())]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);
    insertClientEvent(sinkDb, '2026-11-25T12:30:00.000Z');
    // An IP-bearing row for the same MAC is not client-only and must not count.
    sinkDb.conn
      .prepare(
        "INSERT INTO events (received_at, category, signature, source_ip, source_client_mac, raw) VALUES ('2026-11-25T12:45:00.000Z', 'ips_alert', 'ET MALWARE VenomRAT', '192.168.1.26', ?, 'raw')"
      )
      .run(MAC);
    runHourlyChecks(runnerDeps(sinkDb, lensDb), new Date(now.getTime() + HOUR));

    expect(clientFindings(lensDb)[0].last_activity_at).toBe('2026-11-25T12:30:00.000Z');
  });

  it('keeps a closed client finding closed on fresh activity and on gaining repeat_offender', () => {
    const later = new Date(now.getTime() + HOUR);
    const sinkDb = seededSinkDb([clientRow(now.toISOString())]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);
    closeAs(lensDb, clientFindings(lensDb)[0], 'ai', now.toISOString());

    insertClientEvent(sinkDb, later.toISOString());
    insertClientEvent(sinkDb, '2026-11-22T01:00:00Z');
    insertClientEvent(sinkDb, '2026-11-23T01:00:00Z');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), later);

    const [finding] = clientFindings(lensDb);
    expect(finding.triggers.some((t) => t.type === 'repeat_offender' && t.active)).toBe(true);
    expect(finding.status).toBe('closed');
    expect(finding.last_activity_at).toBe(later.toISOString());
    expect(getPendingRequestForFinding(lensDb, finding.id as number)).toBeNull();
  });

  it('ignores non-Security, IP-bearing and name-only client rows', () => {
    const sinkDb = seededSinkDb([
      clientRow(now.toISOString(), { source_ip: '192.168.1.26', source_client_mac: 'aa:aa:aa:aa:aa:02' }),
      clientRow(now.toISOString(), { category: 'internet_and_wan', source_client_mac: 'aa:aa:aa:aa:aa:03' }),
      clientRow(now.toISOString(), { source_client_mac: null, source_client_name: 'nameonly' }),
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    expect(clientFindings(lensDb)).toEqual([]);
    expect(listFindings(lensDb, { view: 'all' }).some((f) => f.entity_type === 'source_ip' && f.entity_key === '192.168.1.26')).toBe(true);
  });

  it('flags a client repeat offender and lapses it when it drops out of the window', () => {
    const sinkDb = seededSinkDb([
      clientRow('2026-11-23T01:00:00Z'),
      clientRow('2026-11-24T01:00:00Z'),
      clientRow('2026-11-25T01:00:00Z'),
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);
    const repeat = () => clientFindings(lensDb)[0].triggers.find((t) => t.type === 'repeat_offender');
    expect(repeat()?.active).toBe(true);
    expectQueued(lensDb, clientFindings(lensDb)[0]);

    runHourlyChecks(runnerDeps(sinkDb, lensDb), new Date('2026-12-15T12:00:00Z'));
    expect(repeat()?.active).toBe(false);
    expect(clientFindings(lensDb)[0].status).toBe('triaging');
  });

  it('counts only NULL-IP rows toward client repeat-offender days', () => {
    const sinkDb = seededSinkDb([
      clientRow('2026-11-23T01:00:00Z', { source_ip: '192.168.1.26' }),
      clientRow('2026-11-24T01:00:00Z'),
      clientRow('2026-11-25T01:00:00Z'),
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), now);

    const [finding] = clientFindings(lensDb);
    expect(finding.triggers.some((t) => t.type === 'repeat_offender' && t.active)).toBe(false);
  });

  it('still produces IP and signature findings (and their activity) on a pre-v1.0.3 sink', () => {
    const sinkDb = legacySinkDb([
      { received_at: now.toISOString(), category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.5' },
    ]);
    const lensDb = openLensDb(':memory:');
    expect(() => runHourlyChecks(runnerDeps(sinkDb, lensDb), now)).not.toThrow();

    const types = listFindings(lensDb, { view: 'all' }).flatMap((f) => f.triggers.map((t) => t.type));
    expect(types).toContain('new_signature');
    expect(types).toContain('new_source_ip');
    expect(clientFindings(lensDb)).toEqual([]);

    sinkDb.conn
      .prepare("INSERT INTO events (received_at, category, signature, source_ip) VALUES (?, 'ips_alert', 'ET SCAN Nmap', '203.0.113.5')")
      .run('2026-11-25T12:30:00.000Z');
    runHourlyChecks(runnerDeps(sinkDb, lensDb), new Date(now.getTime() + HOUR));
    expect(getFinding(lensDb, 'source_ip', '203.0.113.5')?.last_activity_at).toBe('2026-11-25T12:30:00.000Z');
  });

  it('runRuleTriageBackfill skips client findings', () => {
    const lensDb = openLensDb(':memory:');
    upsertFinding(lensDb, applyTrigger(null, 'new_client', now.toISOString(), 'client', MAC));

    const result = runRuleTriageBackfill(runnerDeps(seededSinkDb([]), lensDb));
    expect(result.checked).toBe(0);
    expect(result.closed).toBe(0);
    expect(clientFindings(lensDb)[0].status).toBe('triaging');
  });
});
