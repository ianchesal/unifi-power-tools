import { describe, expect, it } from 'vitest';
import { applyTrigger, FindingNotFoundError, TransitionError } from '../../src/analysis/findings.js';
import type { Finding } from '../../src/analysis/findings.js';
import type { RuleMatch } from '../../src/analysis/matchRules.js';
import {
  atomically,
  closeByRule,
  humanClose,
  humanReopen,
  queueForAnalysis,
  reanalyze,
  recheckRequeue,
  recheckStillClosed,
  recordCreated,
} from '../../src/analysis/pipeline.js';
import {
  createAnalysisRequest,
  getAnalysisRequest,
  getAnalysisRequestsForFinding,
  getPendingRequestForFinding,
} from '../../src/db/analysisRequestsStore.js';
import { listHistory } from '../../src/db/findingHistoryStore.js';
import { getFindingById, updateFindingState, upsertFinding } from '../../src/db/findingsStore.js';
import { type LensDb, openLensDb } from '../../src/db/lensDb.js';

function triagingFinding(db: LensDb): Finding {
  return upsertFinding(db, applyTrigger(null, 'new_source_ip', 't0', 'source_ip', '203.0.113.7'));
}

function stateFinding(db: LensDb, patch: Parameters<typeof updateFindingState>[2]): Finding {
  const f = triagingFinding(db);
  return updateFindingState(db, f.id as number, patch) as Finding;
}

const closedFinding = (db: LensDb) =>
  stateFinding(db, {
    status: 'closed',
    closed_by: 'rule',
    closed_reason: 'noise',
    closed_at: 't0',
    last_triaged_at: 't0',
  });
const attentionFinding = (db: LensDb) => stateFinding(db, { status: 'attention' });

function match(rule: RuleMatch['rule']): RuleMatch {
  return { rule, verdict: { recommendation: `rec for ${rule}`, riskLevel: 'low' } };
}

describe('pipeline', () => {
  it('recordCreated writes a created history row naming the trigger', () => {
    const db = openLensDb(':memory:');
    const f = triagingFinding(db);
    recordCreated(db, f, 't0');
    const [row] = listHistory(db, f.id as number);
    expect(row).toMatchObject({ kind: 'created', actor: 'system', at: 't0' });
    expect(row.summary).toContain('new_source_ip');
    db.close();
  });

  it('queueForAnalysis creates a request and records queued history', () => {
    const db = openLensDb(':memory:');
    const f = triagingFinding(db);
    const req = queueForAnalysis(db, f, 't1');
    expect(req.status).toBe('pending');
    expect(listHistory(db, f.id as number)).toMatchObject([
      { kind: 'queued', actor: 'system', analysis_request_id: req.id },
    ]);
    db.close();
  });

  it('queueForAnalysis rejects a finding that is not triaging', () => {
    const db = openLensDb(':memory:');
    const f = attentionFinding(db);
    expect(() => queueForAnalysis(db, f, 't1')).toThrow(/triaging/);
    db.close();
  });

  it('closeByRule from triaging cancels the pending request and records both history rows', () => {
    const db = openLensDb(':memory:');
    const f = triagingFinding(db);
    const req = createAnalysisRequest(db, f.id as number, 't0');
    const closed = closeByRule(db, f, match('reputation_blocklist'), 't1');
    expect(closed).toMatchObject({
      status: 'closed',
      closed_by: 'rule',
      closed_reason: 'rec for reputation_blocklist',
      closed_at: 't1',
      last_triaged_at: 't1',
    });
    expect(getAnalysisRequest(db, req.id)?.status).toBe('cancelled');
    expect(listHistory(db, f.id as number).map((h) => h.kind)).toEqual([
      'request_cancelled',
      'rule_closed',
    ]);
    const answered = getAnalysisRequestsForFinding(db, f.id as number).find(
      (r) => r.source === 'rule'
    );
    expect(answered?.status).toBe('answered');
    expect(JSON.parse(answered?.context ?? '{}').rule).toBe('reputation_blocklist');
    const rc = listHistory(db, f.id as number)[1];
    expect(rc).toMatchObject({ actor: 'rule', summary: 'Closed by rule reputation_blocklist' });
    db.close();
  });

  it('closeByRule from attention throws TransitionError and changes nothing', () => {
    const db = openLensDb(':memory:');
    const f = attentionFinding(db);
    expect(() => closeByRule(db, f, match('operational_noise'), 't1')).toThrow(TransitionError);
    expect(getFindingById(db, f.id as number)?.status).toBe('attention');
    expect(listHistory(db, f.id as number)).toEqual([]);
    expect(getAnalysisRequestsForFinding(db, f.id as number)).toEqual([]);
    db.close();
  });

  it('recheckRequeue reopens to triaging, bumps reopen_count and queues a recheck request', () => {
    const db = openLensDb(':memory:');
    const f = closedFinding(db);
    const reopened = recheckRequeue(db, f, 't5');
    expect(reopened).toMatchObject({
      status: 'triaging',
      closed_by: null,
      closed_reason: null,
      closed_at: null,
      reopen_count: 1,
    });
    expect(getPendingRequestForFinding(db, f.id as number)?.is_recheck).toBe(1);
    expect(listHistory(db, f.id as number)).toMatchObject([
      { kind: 'recheck_queued', actor: 'system' },
    ]);
    db.close();
  });

  it('recheckStillClosed updates last_triaged_at only and writes no analysis row', () => {
    const db = openLensDb(':memory:');
    const f = closedFinding(db);
    const out = recheckStillClosed(db, f, match('operational_noise'), 't9');
    expect(out).toMatchObject({
      status: 'closed',
      closed_by: 'rule',
      closed_reason: 'noise',
      closed_at: 't0',
      last_triaged_at: 't9',
    });
    expect(getAnalysisRequestsForFinding(db, f.id as number)).toEqual([]);
    expect(listHistory(db, f.id as number)).toMatchObject([
      { kind: 'recheck_rule_still_closed', actor: 'rule' },
    ]);
    db.close();
  });

  it('humanClose requires attention and uses the note as closed_reason', () => {
    const db = openLensDb(':memory:');
    const f = attentionFinding(db);
    const out = humanClose(db, f.id as number, 'handled', '  rotated the key  ', 't2');
    expect(out).toMatchObject({
      status: 'closed',
      closed_by: 'human',
      closed_reason: 'rotated the key',
      closed_at: 't2',
    });
    expect(listHistory(db, f.id as number)).toMatchObject([
      { kind: 'human_closed_handled', actor: 'human', note: 'rotated the key' },
    ]);
    const closed = closedFinding(db);
    expect(() => humanClose(db, closed.id as number, 'handled', null, 't3')).toThrow(
      TransitionError
    );
    db.close();
  });

  it('humanClose without a note uses "Handled" / "Not a concern"', () => {
    const db = openLensDb(':memory:');
    const a = attentionFinding(db);
    expect(humanClose(db, a.id as number, 'handled', null, 't2').closed_reason).toBe('Handled');
    const b = upsertFinding(db, applyTrigger(null, 'new_source_ip', 't0', 'source_ip', '203.0.113.8'));
    updateFindingState(db, b.id as number, { status: 'attention' });
    const out = humanClose(db, b.id as number, 'not_concern', '   ', 't2');
    expect(out.closed_reason).toBe('Not a concern');
    expect(listHistory(db, b.id as number)[0]).toMatchObject({
      kind: 'human_closed_not_concern',
      note: null,
    });
    db.close();
  });

  it('humanReopen moves a closed finding to attention with the note', () => {
    const db = openLensDb(':memory:');
    const f = closedFinding(db);
    const out = humanReopen(db, f.id as number, 'still seeing it', 't3');
    expect(out).toMatchObject({
      status: 'attention',
      closed_by: null,
      closed_reason: null,
      closed_at: null,
      last_triaged_at: 't3',
    });
    expect(listHistory(db, f.id as number)).toMatchObject([
      { kind: 'human_reopened', actor: 'human', note: 'still seeing it' },
    ]);
    db.close();
  });

  it('humanReopen rejects a blank note', () => {
    const db = openLensDb(':memory:');
    const f = closedFinding(db);
    expect(() => humanReopen(db, f.id as number, '   ', 't1')).toThrow(/note is required/);
    expect(getFindingById(db, f.id as number)?.status).toBe('closed');
    db.close();
  });

  it('reanalyze from closed queues a non-recheck request; from triaging throws', () => {
    const db = openLensDb(':memory:');
    const f = closedFinding(db);
    const out = reanalyze(db, f.id as number, 't4');
    expect(out).toMatchObject({ status: 'triaging', closed_by: null, closed_at: null });
    expect(getPendingRequestForFinding(db, f.id as number)?.is_recheck).toBe(0);
    expect(listHistory(db, f.id as number).map((h) => h.kind)).toEqual(['human_reanalyze']);
    expect(() => reanalyze(db, f.id as number, 't5')).toThrow(TransitionError);
    db.close();
  });

  it('reanalyze from attention cancels nothing and queues a request', () => {
    const db = openLensDb(':memory:');
    const f = attentionFinding(db);
    reanalyze(db, f.id as number, 't4');
    expect(getFindingById(db, f.id as number)?.status).toBe('triaging');
    expect(getPendingRequestForFinding(db, f.id as number)).not.toBeNull();
    db.close();
  });

  it('unknown finding id throws FindingNotFoundError', () => {
    const db = openLensDb(':memory:');
    expect(() => humanClose(db, 999, 'handled', null, 't')).toThrow(FindingNotFoundError);
    expect(() => humanReopen(db, 999, 'x', 't')).toThrow(FindingNotFoundError);
    expect(() => reanalyze(db, 999, 't')).toThrow(FindingNotFoundError);
    db.close();
  });

  it('humanReopen from attention throws TransitionError', () => {
    const db = openLensDb(':memory:');
    const f = attentionFinding(db);
    expect(() => humanReopen(db, f.id as number, 'why', 't1')).toThrow(TransitionError);
    db.close();
  });

  it('recheck functions throw TransitionError from a non-closed finding', () => {
    const db = openLensDb(':memory:');
    const f = triagingFinding(db);
    expect(() => recheckStillClosed(db, f, match('operational_noise'), 't1')).toThrow(
      TransitionError
    );
    expect(() => recheckRequeue(db, f, 't1')).toThrow(TransitionError);
    expect(getPendingRequestForFinding(db, f.id as number)).toBeNull();
    db.close();
  });

  it('recheckRequeue and closeByRule use the stored row, not a stale caller copy', () => {
    const db = openLensDb(':memory:');
    const f = closedFinding(db);
    recheckRequeue(db, f, 't1'); // reopen_count 1
    updateFindingState(db, f.id as number, { status: 'closed', closed_by: 'rule', closed_at: 't2' });
    const again = recheckRequeue(db, f, 't3'); // stale copy still says reopen_count 0
    expect(again.reopen_count).toBe(2);
    updateFindingState(db, f.id as number, { status: 'attention' });
    expect(() => closeByRule(db, { ...f, status: 'triaging' }, match('operational_noise'), 't4')).toThrow(
      TransitionError
    );
    db.close();
  });

  it('nested pipeline calls join the outer transaction and roll back together', () => {
    const db = openLensDb(':memory:');
    const a = attentionFinding(db);
    const b = upsertFinding(
      db,
      applyTrigger(null, 'new_source_ip', 't0', 'source_ip', '203.0.113.9')
    );
    updateFindingState(db, b.id as number, { status: 'closed', closed_by: 'rule', closed_at: 't0' });
    const boom = new Error('boom');
    expect(() =>
      atomically(db, () => {
        humanClose(db, a.id as number, 'handled', null, 't1');
        humanReopen(db, b.id as number, 'again', 't1');
        expect(db.conn.isTransaction).toBe(true);
        throw boom;
      })
    ).toThrow(boom);
    expect(db.conn.isTransaction).toBe(false);
    expect(getFindingById(db, a.id as number)?.status).toBe('attention');
    expect(getFindingById(db, b.id as number)?.status).toBe('closed');
    expect(listHistory(db, a.id as number)).toEqual([]);

    atomically(db, () => {
      humanClose(db, a.id as number, 'handled', null, 't2');
      humanReopen(db, b.id as number, 'again', 't2');
    });
    expect(getFindingById(db, a.id as number)?.status).toBe('closed');
    expect(getFindingById(db, b.id as number)?.status).toBe('attention');
    db.close();
  });
});
