import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { applyTrigger, type Finding } from '../../src/analysis/findings.js';
import { signatureKey } from '../../src/analysis/newEntity.js';
import { applyAiVerdict, queueForAnalysis, recheckRequeue } from '../../src/analysis/pipeline.js';
import {
  type AnalysisRequestRow,
  getPendingRequestForFinding,
} from '../../src/db/analysisRequestsStore.js';
import { getFinding, updateFindingState, upsertFinding } from '../../src/db/findingsStore.js';
import { type LensDb, openLensDb } from '../../src/db/lensDb.js';
import type { EventsDb } from '../../src/db/eventsDb.js';
import type { HomelabRegistry } from '../../src/enrichment/homelabServices.js';
import type { UnifiMcpClient } from '../../src/enrichment/unifiMcpClient.js';
import { type AnalysisDeps, buildAnalysisContext } from '../../src/mcp/context.js';
import { runHourlyChecks } from '../../src/analysis/runner.js';
import { runnerDeps, seededEventsDb } from '../helpers.js';

const NOW = '2026-11-25T12:00:00.000Z';
const FIRST_SEEN = '2026-11-20T00:00:00.000Z';
const IP = '198.51.100.4';
const MAC = 'aa:aa:aa:aa:aa:01';

const stubUnifi: UnifiMcpClient = {
  resolveClient: async () => null,
  getFirewallSummary: async () => null,
};

function deps(lensDb: LensDb, eventsDb: EventsDb | null, homelabServices: HomelabRegistry = {}): AnalysisDeps {
  return { lensDb, eventsDb, unifiMcp: stubUnifi, homelabServices };
}

function ipFinding(db: LensDb): Finding {
  return upsertFinding(db, applyTrigger(null, 'new_source_ip', FIRST_SEEN, 'source_ip', IP));
}

const ok = { verdict: 'close', risk_level: 'low', summary: 'earlier', reasoning: 'r' } as const;
const okCtx = { unblockedIpsAlertsSinceDecision: 0, activeEntryIds: new Set<number>(), operatorBackedEntryIds: new Set<number>() };

describe('buildAnalysisContext', () => {
  it('builds history, prior analyses and since_last_decision counts', async () => {
    const lensDb = openLensDb(':memory:');
    const eventsDb = seededEventsDb([
      // before the first decision (2026-11-21T00:00Z)
      { received_at: '2026-11-20T06:00:00Z', category: 'ips_alert', signature: 'S', source_ip: IP, action: 'allowed' },
      // since the decision: one blocked, one unblocked IPS alert, one firewall event
      { received_at: '2026-11-22T00:00:00Z', category: 'ips_alert', signature: 'S', source_ip: IP, action: 'blocked', dest_ip: '192.168.1.26', dest_port: 8989 },
      { received_at: '2026-11-23T00:00:00Z', category: 'ips_alert', signature: 'S', source_ip: IP, action: null },
      { received_at: '2026-11-24T00:00:00Z', category: 'firewall_block', signature: 'fw', source_ip: IP, action: 'blocked' },
    ]);
    const f = ipFinding(lensDb);
    const first = queueForAnalysis(lensDb, f, FIRST_SEEN);
    const { finding: closed } = applyAiVerdict(lensDb, first.id, ok, okCtx, '2026-11-21T00:00:00.000Z');
    const finding = recheckRequeue(lensDb, closed, '2026-11-25T00:00:00.000Z');
    const request = getPendingRequestForFinding(lensDb, f.id as number) as AnalysisRequestRow;

    const homelab = { '192.168.1.26': { label: 'homelab', services: [{ port: 8989, name: 'sonarr' }] } };
    const ctx = await buildAnalysisContext(deps(lensDb, eventsDb, homelab), request, finding, NOW);

    expect(ctx.finding.id).toBe(f.id);
    expect(ctx.history.map((h) => h.kind)).toEqual(['queued', 'ai_closed', 'recheck_queued']);
    expect(ctx.prior_analyses).toHaveLength(1);
    expect(ctx.prior_analyses[0]).toMatchObject({ id: first.id, verdict: 'close', summary: 'earlier' });
    expect(ctx.prior_analyses[0]).not.toHaveProperty('context');
    expect(ctx.since_last_decision).toEqual({
      since: '2026-11-21T00:00:00.000Z',
      total: 3,
      unblocked_ips_alerts: 1,
    });
    expect(ctx.recentEvents).toHaveLength(4);
    expect(ctx.recentEvents[0].received_at).toBe('2026-11-24T00:00:00Z');
    const annotated = ctx.recentEvents.find((e) => e.dest_port === 8989);
    expect(annotated?.homelab?.service?.name).toBe('sonarr');
    expect(ctx.knownClient).toBeNull();
    expect(ctx.firewallSummary).toBeNull();
    expect(ctx.baselineHistory).toEqual([]);
  });

  it('a never-decided finding measures since_last_decision from first_seen minus 14 days', async () => {
    const lensDb = openLensDb(':memory:');
    const eventsDb = seededEventsDb([
      { received_at: '2026-11-01T00:00:00Z', category: 'ips_alert', signature: 'S', source_ip: IP, action: 'allowed' },
      { received_at: '2026-11-10T00:00:00Z', category: 'ips_alert', signature: 'S', source_ip: IP, action: 'allowed' },
    ]);
    const f = ipFinding(lensDb);
    const request = queueForAnalysis(lensDb, f, FIRST_SEEN);
    const ctx = await buildAnalysisContext(deps(lensDb, eventsDb), request, f, NOW);
    expect(ctx.since_last_decision).toEqual({
      since: '2026-11-06T00:00:00.000Z',
      total: 1,
      unblocked_ips_alerts: 1,
    });
    expect(ctx.prior_analyses).toEqual([]);
    expect(ctx.recheck).toBeNull();
  });

  it('a finding reopened by internal_source after a rule close measures since_last_decision from its creation window', async () => {
    const lensDb = openLensDb(':memory:');
    const eventsDb = seededEventsDb([
      // older than the creation window: not counted
      { received_at: '2026-11-23T06:00:00Z', category: 'ips_alert', signature: 'ET DROP Dshield Block Listed Source group 1', source_ip: '10.0.30.5', action: 'blocked' },
      // the events that created the finding, inside [first_seen - 24h, now)
      { received_at: '2026-11-25T11:30:00Z', category: 'ips_alert', signature: 'ET DROP Dshield Block Listed Source group 1', source_ip: '10.0.30.5', action: 'blocked' },
      { received_at: '2026-11-25T11:45:00Z', category: 'ips_alert', signature: 'ET DROP Dshield Block Listed Source group 1', source_ip: '10.0.30.5', action: 'blocked' },
    ]);
    runHourlyChecks(runnerDeps(eventsDb, lensDb, { lanCidrs: ['10.0.0.0/8'] }), new Date(NOW));
    const finding = getFinding(lensDb, 'source_ip', '10.0.30.5') as Finding;
    // closeByRule stamped last_triaged_at with the run time, then internal_source reopened it.
    expect(finding.status).toBe('triaging');
    expect(finding.last_triaged_at).toBe(NOW);
    const request = getPendingRequestForFinding(lensDb, finding.id as number) as AnalysisRequestRow;

    const ctx = await buildAnalysisContext(deps(lensDb, eventsDb), request, finding, NOW);
    expect(ctx.history.map((h) => h.kind)).toEqual(['created', 'rule_closed', 'trigger_added', 'queued']);
    expect(ctx.since_last_decision).toEqual({
      since: '2026-11-24T12:00:00.000Z',
      total: 2,
      unblocked_ips_alerts: 0,
    });
  });

  it('adds a before/after summary only for recheck requests', async () => {
    const lensDb = openLensDb(':memory:');
    const eventsDb = seededEventsDb([
      // 14-day window before the decision
      { received_at: '2026-11-15T00:00:00Z', category: 'ips_alert', signature: 'S', source_ip: IP, action: 'blocked', dest_port: 22 },
      // outside the before window (older than decision − 14d)
      { received_at: '2026-10-01T00:00:00Z', category: 'ips_alert', signature: 'S', source_ip: IP, action: 'blocked', dest_port: 22 },
      // after the decision
      { received_at: '2026-11-23T00:00:00Z', category: 'ips_alert', signature: 'T', source_ip: IP, action: 'allowed', dest_port: 3389 },
      { received_at: '2026-11-24T00:00:00Z', category: 'ips_alert', signature: 'T', source_ip: IP, action: 'allowed', dest_port: 3389 },
    ]);
    const decided = '2026-11-21T00:00:00.000Z';
    const closed = updateFindingState(lensDb, ipFinding(lensDb).id as number, {
      status: 'closed',
      closed_by: 'rule',
      closed_at: decided,
      last_triaged_at: decided,
    }) as Finding;
    const reopened = recheckRequeue(lensDb, closed, '2026-11-25T00:00:00.000Z');
    const recheckReq = getPendingRequestForFinding(lensDb, closed.id as number) as AnalysisRequestRow;

    const ctx = await buildAnalysisContext(deps(lensDb, eventsDb), recheckReq, reopened, NOW);
    expect(ctx.recheck?.before.total).toBe(1);
    expect(ctx.recheck?.before.top_dest_ports).toEqual([{ value: 22, count: 1 }]);
    expect(ctx.recheck?.after.total).toBe(2);
    expect(ctx.recheck?.after.top_counterparts).toEqual([{ value: 'T', count: 2 }]);

    const plain = { ...recheckReq, is_recheck: 0 };
    const ctx2 = await buildAnalysisContext(deps(lensDb, eventsDb), plain, reopened, NOW);
    expect(ctx2.recheck).toBeNull();
    expect(ctx2.since_last_decision?.total).toBe(2);
  });

  it('includes baseline history for a signature finding', async () => {
    const lensDb = openLensDb(':memory:');
    const eventsDb = seededEventsDb([
      { received_at: '2026-11-19T00:00:00Z', category: 'firewall_block', signature: 'weird-sig' },
    ]);
    lensDb.conn
      .prepare('INSERT INTO baselines (category, signature, day, count) VALUES (?, ?, ?, ?)')
      .run('firewall_block', 'weird-sig', '2026-11-18', 4);
    const f = upsertFinding(
      lensDb,
      applyTrigger(null, 'new_signature', FIRST_SEEN, 'signature', signatureKey('firewall_block', 'weird-sig'))
    );
    const request = queueForAnalysis(lensDb, f, FIRST_SEEN);
    const ctx = await buildAnalysisContext(deps(lensDb, eventsDb), request, f, NOW);
    expect(ctx.recentEvents).toHaveLength(1);
    expect(ctx.baselineHistory).toEqual([{ day: '2026-11-18', count: 4 }]);
  });

  it('builds a client finding from its MAC with a display name', async () => {
    const lensDb = openLensDb(':memory:');
    const eventsDb = seededEventsDb([
      { received_at: '2026-11-19T00:00:00Z', category: 'ips_alert', signature: 'sig', source_client_mac: MAC, source_client_name: 'tranquility', action: 'allowed' },
    ]);
    const f = upsertFinding(lensDb, applyTrigger(null, 'new_client', FIRST_SEEN, 'client', MAC));
    const request = queueForAnalysis(lensDb, f, FIRST_SEEN);
    const ctx = await buildAnalysisContext(deps(lensDb, eventsDb), request, f, NOW);
    expect(ctx.recentEvents).toHaveLength(1);
    expect(ctx.recentEvents[0]).toMatchObject({ source_client_mac: MAC });
    expect(ctx.knownClient).toBeNull();
    expect(ctx.finding).toMatchObject({ display_name: 'tranquility' });
    expect(ctx.since_last_decision).toMatchObject({ total: 1, unblocked_ips_alerts: 1 });
  });

  it('degrades without a sink: empty events, null since_last_decision and recheck', async () => {
    const lensDb = openLensDb(':memory:');
    const closed = updateFindingState(lensDb, ipFinding(lensDb).id as number, {
      status: 'closed',
      closed_by: 'rule',
      closed_at: '2026-11-21T00:00:00.000Z',
    }) as Finding;
    const reopened = recheckRequeue(lensDb, closed, '2026-11-25T00:00:00.000Z');
    const request = getPendingRequestForFinding(lensDb, closed.id as number) as AnalysisRequestRow;
    const ctx = await buildAnalysisContext(deps(lensDb, null), request, reopened, NOW);
    expect(ctx.recentEvents).toEqual([]);
    expect(ctx.baselineHistory).toEqual([]);
    expect(ctx.since_last_decision).toBeNull();
    expect(ctx.recheck).toBeNull();
    expect(ctx.history.map((h) => h.kind)).toEqual(['recheck_queued']);
  });

  it('a failing events query yields null since_last_decision, not a throw', async () => {
    const conn = new DatabaseSync(':memory:');
    conn.exec(
      `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
       category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
       dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
       signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER)`
    );
    const lensDb = openLensDb(':memory:');
    const f = upsertFinding(lensDb, applyTrigger(null, 'new_client', FIRST_SEEN, 'client', MAC));
    const request = { ...queueForAnalysis(lensDb, f, FIRST_SEEN), is_recheck: 1 };
    const ctx = await buildAnalysisContext(deps(lensDb, { conn }), request, f, NOW);
    expect(ctx.recentEvents).toEqual([]);
    expect(ctx.since_last_decision).toBeNull();
    expect(ctx.recheck).toBeNull();
    expect(ctx.finding).toMatchObject({ display_name: null });
  });
});
