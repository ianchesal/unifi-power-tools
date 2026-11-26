import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import type { Finding } from '../../src/analysis/findings.js';
import {
  bumpLastActivity,
  closedCountsSince,
  countFindings,
  getFinding,
  getFindingById,
  hasSeenSourceIp,
  listFindings,
  markSeenClient,
  markSeenSourceIp,
  seenClientMacs,
  updateFindingState,
  upsertFinding,
} from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';

function seed(
  db: ReturnType<typeof openLensDb>,
  key: string,
  patch: Partial<Finding> = {}
): Finding {
  const base = applyTrigger(null, 'internal_source', 't0', 'source_ip', key);
  return upsertFinding(db, { ...base, ...patch });
}

describe('findingsStore', () => {
  it('round-trips a finding through upsert/get, preserving triggers', () => {
    const db = openLensDb(':memory:');
    const finding = applyTrigger(null, 'internal_source', 't0', 'source_ip', '192.0.2.4');
    const saved = upsertFinding(db, finding);
    expect(saved.id).toBeDefined();

    const fetched = getFinding(db, 'source_ip', '192.0.2.4');
    expect(fetched?.triggers).toEqual(finding.triggers);
    expect(fetched?.status).toBe('triaging');
    expect(fetched?.last_activity_at).toBe('t0');
    expect(fetched?.reopen_count).toBe(0);
    expect(getFindingById(db, saved.id as number)?.entity_key).toBe('192.0.2.4');
    expect(getFindingById(db, 999)).toBeNull();
    db.close();
  });

  it('upsert on the same entity updates the same row (no duplicate)', () => {
    const db = openLensDb(':memory:');
    const f1 = upsertFinding(db, applyTrigger(null, 'internal_source', 't0', 'source_ip', '198.51.100.9'));
    const f2 = upsertFinding(db, applyTrigger(f1, 'repeat_offender', 't1', 'source_ip', '198.51.100.9'));
    expect(f2.id).toBe(f1.id);
    expect(listFindings(db).length).toBe(1);
    db.close();
  });

  it('upsert persists closed fields and status changes', () => {
    const db = openLensDb(':memory:');
    const f = seed(db, '198.51.100.9');
    const saved = upsertFinding(db, {
      ...f,
      status: 'closed',
      closed_by: 'rule',
      closed_reason: 'noise',
      closed_at: 't5',
    });
    expect(saved).toMatchObject({
      status: 'closed',
      closed_by: 'rule',
      closed_reason: 'noise',
      closed_at: 't5',
    });
    db.close();
  });

  it('tracks seen source IPs', () => {
    const db = openLensDb(':memory:');
    expect(hasSeenSourceIp(db, '192.0.2.100')).toBe(false);
    markSeenSourceIp(db, '192.0.2.100', 't0');
    expect(hasSeenSourceIp(db, '192.0.2.100')).toBe(true);
    db.close();
  });

  it('updateFindingState patches only the given fields and returns the finding', () => {
    const db = openLensDb(':memory:');
    const f = seed(db, '198.51.100.9');
    const updated = updateFindingState(db, f.id as number, {
      status: 'closed',
      closed_by: 'human',
      closed_reason: 'ok',
      closed_at: 't2',
      reopen_count: 3,
    });
    expect(updated).toMatchObject({
      status: 'closed',
      closed_by: 'human',
      closed_reason: 'ok',
      closed_at: 't2',
      reopen_count: 3,
      last_triaged_at: null,
    });
    const cleared = updateFindingState(db, f.id as number, {
      status: 'triaging',
      closed_by: null,
      closed_reason: null,
      closed_at: null,
    });
    expect(cleared).toMatchObject({ status: 'triaging', closed_by: null, reopen_count: 3 });
    expect(updateFindingState(db, f.id as number, {})?.id).toBe(f.id);
    db.close();
  });

  it('updateFindingState returns null for a nonexistent finding id', () => {
    const db = openLensDb(':memory:');
    expect(updateFindingState(db, 999, { status: 'closed' })).toBeNull();
  });

  it('defaults to open findings (attention + triaging) and filters by view', () => {
    const db = openLensDb(':memory:');
    seed(db, '10.0.0.1', { status: 'triaging' });
    seed(db, '10.0.0.2', { status: 'attention' });
    seed(db, '10.0.0.3', { status: 'closed', closed_by: 'rule', closed_reason: 'x', closed_at: 't1' });
    expect(listFindings(db)).toHaveLength(2);
    expect(countFindings(db)).toBe(2);
    expect(listFindings(db, { view: 'closed' })).toHaveLength(1);
    expect(listFindings(db, { view: 'attention' }).map((f) => f.entity_key)).toEqual(['10.0.0.2']);
    expect(listFindings(db, { view: 'triaging' }).map((f) => f.entity_key)).toEqual(['10.0.0.1']);
    expect(listFindings(db, { view: 'all' })).toHaveLength(3);
    expect(countFindings(db, { view: 'all' })).toBe(3);
    db.close();
  });

  it('orders open by severity desc then first_seen asc, with pagination', () => {
    const db = openLensDb(':memory:');
    seed(db, '10.0.0.1', { severity_score: 1, first_seen: 't2' });
    seed(db, '10.0.0.2', { severity_score: 3, first_seen: 't3' });
    seed(db, '10.0.0.3', { severity_score: 3, first_seen: 't1' });
    expect(listFindings(db).map((f) => f.entity_key)).toEqual(['10.0.0.3', '10.0.0.2', '10.0.0.1']);
    expect(listFindings(db, { limit: 1, offset: 1 }).map((f) => f.entity_key)).toEqual(['10.0.0.2']);
    db.close();
  });

  it('filters closed findings by closed_by and q, ordered by closed_at desc', () => {
    const db = openLensDb(':memory:');
    seed(db, '10.0.0.1', { status: 'closed', closed_by: 'rule', closed_reason: 'Port SCAN noise', closed_at: 't1' });
    seed(db, '10.0.0.2', { status: 'closed', closed_by: 'ai', closed_reason: 'scan again', closed_at: 't3' });
    seed(db, '10.0.0.3', { status: 'closed', closed_by: 'human', closed_reason: 'other', closed_at: 't2' });
    expect(listFindings(db, { view: 'closed' }).map((f) => f.entity_key)).toEqual([
      '10.0.0.2',
      '10.0.0.3',
      '10.0.0.1',
    ]);
    expect(listFindings(db, { view: 'closed', closedBy: 'rule' }).map((f) => f.entity_key)).toEqual(['10.0.0.1']);
    expect(listFindings(db, { view: 'closed', q: 'scan' }).map((f) => f.entity_key)).toEqual([
      '10.0.0.2',
      '10.0.0.1',
    ]);
    expect(countFindings(db, { view: 'closed', q: '10.0.0.3' })).toBe(1);
    db.close();
  });

  it('q treats % _ and quotes literally', () => {
    const db = openLensDb(':memory:');
    const reasons = ['100% blocked', 'a_b', "it's fine", 'plain'];
    reasons.forEach((r, i) =>
      seed(db, `10.0.0.${i + 1}`, { status: 'closed', closed_by: 'human', closed_reason: r, closed_at: `t${i}` })
    );
    expect(listFindings(db, { view: 'closed', q: '%' }).map((f) => f.closed_reason)).toEqual(['100% blocked']);
    expect(listFindings(db, { view: 'closed', q: '_' }).map((f) => f.closed_reason)).toEqual(['a_b']);
    expect(listFindings(db, { view: 'closed', q: "'" }).map((f) => f.closed_reason)).toEqual(["it's fine"]);
    db.close();
  });

  it('upsertFinding does not overwrite last_activity_at, last_triaged_at or reopen_count', () => {
    const db = openLensDb(':memory:');
    const f = seed(db, '198.51.100.9');
    bumpLastActivity(db, 'source_ip', '198.51.100.9', 't9');
    updateFindingState(db, f.id as number, { last_triaged_at: 't8', reopen_count: 2 });
    const again = upsertFinding(db, { ...f, last_seen: 't10' });
    expect(again).toMatchObject({
      last_seen: 't10',
      last_activity_at: 't9',
      last_triaged_at: 't8',
      reopen_count: 2,
    });
    db.close();
  });

  it('bumpLastActivity only moves forward', () => {
    const db = openLensDb(':memory:');
    seed(db, '198.51.100.9');
    bumpLastActivity(db, 'source_ip', '198.51.100.9', 't5');
    expect(getFinding(db, 'source_ip', '198.51.100.9')?.last_activity_at).toBe('t5');
    bumpLastActivity(db, 'source_ip', '198.51.100.9', 't3');
    expect(getFinding(db, 'source_ip', '198.51.100.9')?.last_activity_at).toBe('t5');
    db.close();
  });

  it('closedCountsSince counts by closed_by and zero-fills', () => {
    const db = openLensDb(':memory:');
    seed(db, '10.0.0.1', { status: 'closed', closed_by: 'rule', closed_reason: 'x', closed_at: 't1' });
    seed(db, '10.0.0.2', { status: 'closed', closed_by: 'human', closed_reason: 'x', closed_at: 't2' });
    seed(db, '10.0.0.3', { status: 'closed', closed_by: 'human', closed_reason: 'x', closed_at: 't3' });
    seed(db, '10.0.0.4', { status: 'closed', closed_by: 'ai', closed_reason: 'x', closed_at: 's0' });
    seed(db, '10.0.0.5', { status: 'attention' });
    expect(closedCountsSince(db, 't0')).toEqual({ rule: 1, ai: 0, human: 2, system: 0 });
    db.close();
  });

  it('tracks seen client MACs', () => {
    const db = openLensDb(':memory:');
    expect(seenClientMacs(db)).toEqual(new Set());
    markSeenClient(db, 'aa:bb:cc:dd:ee:ff', 't0');
    markSeenClient(db, 'aa:bb:cc:dd:ee:ff', 't1');
    expect(seenClientMacs(db)).toEqual(new Set(['aa:bb:cc:dd:ee:ff']));
  });
});
