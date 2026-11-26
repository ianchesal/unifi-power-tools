import { describe, expect, it } from 'vitest';
import { applyTrigger, type Finding } from '../../src/analysis/findings.js';
import { matchRules } from '../../src/analysis/matchRules.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';
import { runnerDeps, seededEventsDb } from '../helpers.js';

const SINCE = '2026-11-24T00:00:00.000Z';
const AT = '2026-11-24T12:00:00.000Z';
const IP = '203.0.113.7';

function ipFinding(lensDb: ReturnType<typeof openLensDb>, extra?: 'internal'): Finding {
  let f = upsertFinding(
    lensDb,
    applyTrigger(null, 'new_source_ip', AT, 'source_ip', IP)
  );
  if (extra === 'internal') {
    f = upsertFinding(lensDb, applyTrigger(f, 'internal_source', AT, 'source_ip', IP));
  }
  return f;
}

const blocked = (signature = 'ET DROP Dshield Block') => ({
  received_at: AT,
  category: 'ips_alert',
  signature,
  source_ip: IP,
  action: 'blocked',
});

describe('matchRules', () => {
  it('matches reputation_blocklist when every event is a blocked safe-prefix hit', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(seededEventsDb([blocked(), blocked('ET CINS Active Threat')]), lensDb);
    expect(matchRules(deps, ipFinding(lensDb), SINCE)?.rule).toBe('reputation_blocklist');
  });

  it('returns the verdict alongside the rule', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(seededEventsDb([blocked()]), lensDb);
    const match = matchRules(deps, ipFinding(lensDb), SINCE);
    expect(match?.verdict.riskLevel).toBe('low');
    expect(match?.verdict.recommendation).toBeTruthy();
  });

  it('returns null when one event falls outside the rule', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(
      seededEventsDb([blocked(), { ...blocked('ET SCAN Nmap'), action: 'alert' }]),
      lensDb
    );
    expect(matchRules(deps, ipFinding(lensDb), SINCE)).toBeNull();
  });

  it('returns null when the window has no events (total 0)', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(seededEventsDb([]), lensDb);
    expect(matchRules(deps, ipFinding(lensDb), SINCE)).toBeNull();
  });

  it('respects the untilIso upper bound', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(seededEventsDb([blocked()]), lensDb);
    expect(matchRules(deps, ipFinding(lensDb), SINCE, '2026-11-24T06:00:00.000Z')).toBeNull();
  });

  it('a finding carrying internal_source can only match operational_noise', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(seededEventsDb([blocked()]), lensDb);
    // Without the flag the same events match reputation_blocklist.
    expect(matchRules(deps, ipFinding(lensDb), SINCE)?.rule).toBe('reputation_blocklist');
    const internal = { ...ipFinding(lensDb, 'internal') };
    expect(internal.triggers.some((t) => t.type === 'internal_source')).toBe(true);
    expect(matchRules(deps, internal, SINCE)).toBeNull();
  });

  it('internal-source restriction still allows operational_noise', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(
      seededEventsDb([{ received_at: AT, category: 'internet_and_wan', signature: null, source_ip: IP }]),
      lensDb
    );
    const f = ipFinding(lensDb, 'internal');
    expect(matchRules(deps, f, SINCE)?.rule).toBe('operational_noise');
  });

  it('intersects allowedRules with operational_noise for internal findings', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(
      seededEventsDb([{ received_at: AT, category: 'internet_and_wan', signature: null, source_ip: IP }]),
      lensDb
    );
    const f = ipFinding(lensDb, 'internal');
    expect(matchRules(deps, f, SINCE, undefined, ['reputation_blocklist'])).toBeNull();
    expect(matchRules(deps, f, SINCE, undefined, ['operational_noise'])?.rule).toBe(
      'operational_noise'
    );
  });

  it('honours allowedRules for non-internal findings', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(seededEventsDb([blocked()]), lensDb);
    expect(
      matchRules(deps, ipFinding(lensDb), SINCE, undefined, ['operational_noise'])
    ).toBeNull();
  });

  it('never matches a client finding', () => {
    const lensDb = openLensDb(':memory:');
    const mac = 'aa:bb:cc:00:11:22';
    const deps = runnerDeps(
      seededEventsDb([
        {
          received_at: AT,
          category: 'ips_alert',
          signature: 'ET DROP x',
          action: 'blocked',
          source_client_mac: mac,
        },
      ]),
      lensDb
    );
    const clientFinding = upsertFinding(
      lensDb,
      applyTrigger(null, 'new_client', AT, 'client', mac)
    );
    expect(matchRules(deps, clientFinding, SINCE)).toBeNull();
  });

  it('matches a signature finding via ignored_signature', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(seededEventsDb([]), lensDb);
    const f = upsertFinding(
      lensDb,
      applyTrigger(null, 'new_signature', AT, 'signature', 'siteactivity|2154')
    );
    expect(matchRules(deps, f, SINCE)?.rule).toBe('ignored_signature');
  });

  it('is query-only: no analysis rows or status changes', () => {
    const lensDb = openLensDb(':memory:');
    const deps = runnerDeps(seededEventsDb([blocked()]), lensDb);
    const f = ipFinding(lensDb);
    expect(matchRules(deps, f, SINCE)).not.toBeNull();
    const rows = lensDb.conn.prepare('SELECT COUNT(*) AS n FROM analysis_requests').get() as {
      n: number;
    };
    expect(rows.n).toBe(0);
    const after = lensDb.conn.prepare('SELECT status FROM findings WHERE id = ?').get(f.id as number) as {
      status: string;
    };
    expect(after.status).toBe(f.status);
  });
});
