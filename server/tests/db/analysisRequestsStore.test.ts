import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import type { Finding } from '../../src/analysis/findings.js';
import {
  cancelPendingRequests,
  createAnalysisRequest,
  createAnsweredRuleAnalysis,
  getAnalysisRequestsForFinding,
  getPendingAnalysisRequests,
  getPendingRequestForFinding,
  getQueueStats,
  latestAnsweredAnalyses,
  recordAiVerdict,
  updateRequestContext,
} from '../../src/db/analysisRequestsStore.js';
import type { AiVerdictFields } from '../../src/db/analysisRequestsStore.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';

const fields: AiVerdictFields = {
  verdict: 'close',
  risk_level: 'low',
  summary: 'benign',
  reasoning: 'looks benign',
};

function mk(db: ReturnType<typeof openLensDb>, key: string, patch: Partial<Finding> = {}): number {
  const base = applyTrigger(null, 'internal_source', 't0', 'source_ip', key);
  return upsertFinding(db, { ...base, ...patch }).id as number;
}

describe('analysisRequestsStore', () => {
  it('createAnalysisRequest stores empty context and the recheck flag', () => {
    const db = openLensDb(':memory:');
    const id = mk(db, '192.0.2.4');
    const r = createAnalysisRequest(db, id, 't1', { isRecheck: true });
    expect(r).toMatchObject({ context: '{}', is_recheck: 1, status: 'pending', source: 'ai' });
    expect(createAnalysisRequest(db, mk(db, '192.0.2.5'), 't1').is_recheck).toBe(0);
    expect(getPendingAnalysisRequests(db)).toHaveLength(2);
    db.close();
  });

  it('dedupes a second request while one is still pending', () => {
    const db = openLensDb(':memory:');
    const id = mk(db, '192.0.2.4');
    const first = createAnalysisRequest(db, id, 't1');
    const second = createAnalysisRequest(db, id, 't2');
    expect(second.id).toBe(first.id);
    expect(getPendingRequestForFinding(db, id)?.id).toBe(first.id);
    expect(getPendingAnalysisRequests(db)).toHaveLength(1);
    db.close();
  });

  it('allows a fresh request once the prior one is answered', () => {
    const db = openLensDb(':memory:');
    const id = mk(db, '192.0.2.4');
    const first = createAnalysisRequest(db, id, 't1');
    recordAiVerdict(db, first.id, fields, 't2');
    expect(getPendingRequestForFinding(db, id)).toBeNull();
    expect(createAnalysisRequest(db, id, 't3').id).not.toBe(first.id);
    db.close();
  });

  it('recordAiVerdict stores verdict fields, reasoning as recommendation', () => {
    const db = openLensDb(':memory:');
    const r = createAnalysisRequest(db, mk(db, '192.0.2.4'), 't1');
    const done = recordAiVerdict(
      db,
      r.id,
      { ...fields, verdict: 'attention', recommended_action: 'block it', why_now: 'spike', cited_entries: [3, 4] },
      't2'
    );
    expect(done).toMatchObject({
      status: 'answered',
      source: 'ai',
      verdict: 'attention',
      risk_level: 'low',
      summary: 'benign',
      recommendation: 'looks benign',
      recommended_action: 'block it',
      why_now: 'spike',
      cited_entries: '[3,4]',
      answered_at: 't2',
    });
    const plain = recordAiVerdict(db, createAnalysisRequest(db, mk(db, '192.0.2.5'), 't1').id, fields, 't2');
    expect(plain).toMatchObject({ recommended_action: null, why_now: null, cited_entries: null });
    db.close();
  });

  it('throws recording to an already-answered or missing request', () => {
    const db = openLensDb(':memory:');
    const r = createAnalysisRequest(db, mk(db, '192.0.2.4'), 't1');
    recordAiVerdict(db, r.id, fields, 't2');
    expect(() => recordAiVerdict(db, r.id, fields, 't3')).toThrow(/already answered/);
    expect(() => recordAiVerdict(db, 999, fields, 't3')).toThrow('Analysis request 999 not found');
    db.close();
  });

  it('cancelPendingRequests cancels only the pending row and returns it', () => {
    const db = openLensDb(':memory:');
    const id = mk(db, '192.0.2.4');
    const answered = createAnalysisRequest(db, id, 't1');
    recordAiVerdict(db, answered.id, fields, 't2');
    const pending = createAnalysisRequest(db, id, 't3');
    const other = createAnalysisRequest(db, mk(db, '192.0.2.5'), 't3');

    const cancelled = cancelPendingRequests(db, id);
    expect(cancelled.map((r) => r.id)).toEqual([pending.id]);
    expect(cancelled[0].status).toBe('cancelled');
    const rows = getAnalysisRequestsForFinding(db, id);
    expect(rows.map((r) => r.status)).toEqual(['answered', 'cancelled']);
    expect(getPendingAnalysisRequests(db).map((r) => r.id)).toEqual([other.id]);
    expect(cancelPendingRequests(db, id)).toEqual([]);
    db.close();
  });

  it('recordAiVerdict refuses a cancelled request with a skip message', () => {
    const db = openLensDb(':memory:');
    const id = mk(db, '192.0.2.4');
    const r = createAnalysisRequest(db, id, 't1');
    cancelPendingRequests(db, id);
    expect(() => recordAiVerdict(db, r.id, fields, 't2')).toThrow(/cancelled.*skip it/);
    db.close();
  });

  it('updateRequestContext only updates while pending', () => {
    const db = openLensDb(':memory:');
    const r = createAnalysisRequest(db, mk(db, '192.0.2.4'), 't1');
    updateRequestContext(db, r.id, { a: 1 });
    expect(getPendingRequestForFinding(db, r.finding_id)?.context).toBe('{"a":1}');
    recordAiVerdict(db, r.id, fields, 't2');
    updateRequestContext(db, r.id, { a: 2 });
    expect(getAnalysisRequestsForFinding(db, r.finding_id)[0].context).toBe('{"a":1}');
    db.close();
  });

  it('getPendingAnalysisRequests orders by severity then age and honours limit', () => {
    const db = openLensDb(':memory:');
    const low = mk(db, '192.0.2.1', { severity_score: 1 });
    const highOld = mk(db, '192.0.2.2', { severity_score: 5 });
    const highNew = mk(db, '192.0.2.3', { severity_score: 5 });
    createAnalysisRequest(db, low, 't1');
    createAnalysisRequest(db, highNew, 't3');
    createAnalysisRequest(db, highOld, 't2');
    const rows = getPendingAnalysisRequests(db);
    expect(rows.map((r) => r.finding_id)).toEqual([highOld, highNew, low]);
    expect(rows[0]).toMatchObject({ entity_type: 'source_ip', entity_key: '192.0.2.2', severity_score: 5 });
    expect(getPendingAnalysisRequests(db, { limit: 2 })).toHaveLength(2);
    db.close();
  });

  it('getQueueStats ignores rule-sourced answers for last_answered_at', () => {
    const db = openLensDb(':memory:');
    expect(getQueueStats(db)).toEqual({ count: 0, oldest_created_at: null, last_answered_at: null });
    const id = mk(db, '192.0.2.4');
    createAnsweredRuleAnalysis(db, id, {}, 'rule says', 'low', 't9');
    createAnalysisRequest(db, mk(db, '192.0.2.5'), 't4');
    createAnalysisRequest(db, mk(db, '192.0.2.6'), 't3');
    expect(getQueueStats(db)).toEqual({ count: 2, oldest_created_at: 't3', last_answered_at: null });
    const r = createAnalysisRequest(db, id, 't5');
    recordAiVerdict(db, r.id, fields, 't6');
    expect(getQueueStats(db).last_answered_at).toBe('t6');
    db.close();
  });

  it('latestAnsweredAnalyses returns the most recent answered row per finding', () => {
    const db = openLensDb(':memory:');
    const a = mk(db, '192.0.2.4');
    const b = mk(db, '192.0.2.5');
    const c = mk(db, '192.0.2.6');
    const a1 = createAnalysisRequest(db, a, 't1');
    recordAiVerdict(db, a1.id, fields, 't2');
    const a2 = createAnalysisRequest(db, a, 't3');
    recordAiVerdict(db, a2.id, { ...fields, summary: 'newer' }, 't4');
    createAnalysisRequest(db, a, 't5');
    createAnsweredRuleAnalysis(db, b, {}, 'rule', 'low', 't1');
    createAnalysisRequest(db, c, 't1');
    const m = latestAnsweredAnalyses(db, [a, b, c]);
    expect(m.get(a)?.summary).toBe('newer');
    expect(m.get(b)?.source).toBe('rule');
    expect(m.has(c)).toBe(false);
    expect(latestAnsweredAnalyses(db, []).size).toBe(0);
    db.close();
  });

  it('createAnsweredRuleAnalysis inserts an already-answered, rule-sourced close verdict', () => {
    const db = openLensDb(':memory:');
    const finding = upsertFinding(db, applyTrigger(null, 'internal_source', 't0', 'source_ip', '192.0.2.4'));
    const request = createAnsweredRuleAnalysis(
      db,
      finding.id as number,
      { finding },
      'auto-dismissed: routine blocklist scan',
      'low',
      't1'
    );
    expect(request).toMatchObject({
      status: 'answered',
      source: 'rule',
      recommendation: 'auto-dismissed: routine blocklist scan',
      summary: 'auto-dismissed: routine blocklist scan',
      verdict: 'close',
      risk_level: 'low',
      answered_at: 't1',
    });
    db.close();
  });
});
