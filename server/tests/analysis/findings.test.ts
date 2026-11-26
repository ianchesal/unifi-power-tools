import { describe, expect, it } from 'vitest';
import {
  applyTrigger,
  assertTransition,
  type ClosedBy,
  computeSeverityScore,
  decisionWindowStart,
  type Finding,
  type FindingStatus,
  isRecheckDue,
  reevaluateTrigger,
  STANDING_TRIGGER_TYPES,
  TransitionError,
  type Trigger,
} from '../../src/analysis/findings.js';

const base: Finding = applyTrigger(null, 'new_source_ip', 't0', 'source_ip', 'x');

describe('applyTrigger', () => {
  it('creates a new finding as triaging with empty close fields', () => {
    const f = applyTrigger(null, 'new_source_ip', 't0', 'source_ip', '203.0.113.5');
    expect(f).toMatchObject({
      status: 'triaging',
      closed_by: null,
      closed_reason: null,
      closed_at: null,
      last_activity_at: 't0',
      last_triaged_at: null,
      reopen_count: 0,
    });
    expect(f.triggers[0]).toMatchObject({ type: 'new_source_ip', active: true });
  });

  it('refreshes an existing trigger of the same type without touching status', () => {
    let finding = applyTrigger(null, 'repeat_offender', 't0', 'source_ip', '203.0.113.5');
    finding = { ...finding, status: 'attention' };
    finding = applyTrigger(finding, 'repeat_offender', 't1', 'source_ip', '203.0.113.5');
    expect(finding.status).toBe('attention');
    expect(finding.triggers).toHaveLength(1);
    expect(finding.triggers[0].last_seen).toBe('t1');
  });

  it('a new trigger type does not reopen a closed finding', () => {
    const closed = { ...base, status: 'closed' as const, closed_by: 'ai' as const, closed_at: 't1' };
    const f = applyTrigger(closed, 'repeat_offender', 't2', 'source_ip', 'x');
    expect(f.status).toBe('closed');
    expect(f.triggers.map((t) => t.type).sort()).toEqual(['new_source_ip', 'repeat_offender']);
  });

  it('gaining internal_source sends a rule-closed finding back to triaging and clears close fields', () => {
    const ruleClosed = {
      ...base,
      status: 'closed' as const,
      closed_by: 'rule' as const,
      closed_reason: 'r',
      closed_at: 't1',
    };
    expect(applyTrigger(ruleClosed, 'internal_source', 't2', 'source_ip', 'x')).toMatchObject({
      status: 'triaging',
      closed_by: null,
      closed_reason: null,
      closed_at: null,
    });
  });

  it('gaining internal_source leaves an AI- or human-closed finding closed', () => {
    for (const by of ['ai', 'human'] as const) {
      const closed = { ...base, status: 'closed' as const, closed_by: by, closed_reason: 'r', closed_at: 't1' };
      expect(applyTrigger(closed, 'internal_source', 't2', 'source_ip', 'x')).toMatchObject({
        status: 'closed',
        closed_by: by,
        closed_reason: 'r',
        closed_at: 't1',
      });
    }
  });

  it('refreshing an existing internal_source trigger does not reopen a rule-closed finding', () => {
    const withInternal = applyTrigger(base, 'internal_source', 't1', 'source_ip', 'x');
    const ruleClosed = { ...withInternal, status: 'closed' as const, closed_by: 'rule' as const, closed_at: 't2' };
    expect(applyTrigger(ruleClosed, 'internal_source', 't3', 'source_ip', 'x').status).toBe('closed');
  });
});

describe('reevaluateTrigger', () => {
  it('marks a standing trigger inactive when its condition lifts', () => {
    let finding = applyTrigger(null, 'anomaly', 't0', 'signature', 'ips_alert|sig-1');
    finding = reevaluateTrigger(finding, 'anomaly', false, 't1');
    expect(finding.triggers[0].active).toBe(false);
  });

  it('a standing trigger lifting or reactivating never changes status', () => {
    for (const status of ['triaging', 'attention', 'closed'] as const) {
      let finding: Finding = {
        ...applyTrigger(null, 'anomaly', 't0', 'signature', 'ips_alert|sig-1'),
        status,
      };
      finding = reevaluateTrigger(finding, 'anomaly', false, 't1');
      expect(finding.status).toBe(status);
      expect(finding.triggers[0].active).toBe(false);
      finding = applyTrigger(finding, 'anomaly', 't2', 'signature', 'ips_alert|sig-1');
      expect(finding.status).toBe(status);
      expect(finding.triggers[0].active).toBe(true);
    }
  });

  it('classification: only anomaly and repeat_offender are standing trigger types', () => {
    expect([...STANDING_TRIGGER_TYPES].sort()).toEqual(['anomaly', 'repeat_offender']);
  });

  it('is a no-op when the finding does not carry that trigger type', () => {
    const finding = applyTrigger(null, 'repeat_offender', 't0', 'source_ip', '203.0.113.5');
    expect(reevaluateTrigger(finding, 'anomaly', false, 't1')).toEqual(finding);
  });
});

describe('assertTransition', () => {
  it('allows exactly the spec table', () => {
    const at = (s: FindingStatus, by: ClosedBy | null = null) => ({ ...base, status: s, closed_by: by });
    expect(() => assertTransition('rule_close', at('triaging'))).not.toThrow();
    expect(() => assertTransition('rule_close', at('attention'))).toThrow(TransitionError);
    expect(() => assertTransition('human_close', at('attention'))).not.toThrow();
    expect(() => assertTransition('human_close', at('triaging'))).toThrow(TransitionError);
    expect(() => assertTransition('human_reopen', at('closed', 'ai'))).not.toThrow();
    expect(() => assertTransition('human_reopen', at('attention'))).toThrow(TransitionError);
    expect(() => assertTransition('reanalyze', at('closed', 'rule'))).not.toThrow();
    expect(() => assertTransition('reanalyze', at('attention'))).not.toThrow();
    expect(() => assertTransition('reanalyze', at('triaging'))).toThrow(TransitionError);
    expect(() => assertTransition('submit_analysis', at('triaging'))).not.toThrow();
    expect(() => assertTransition('submit_analysis', at('closed', 'ai'))).toThrow(TransitionError);
    expect(() => assertTransition('recheck', at('closed', 'ai'))).not.toThrow();
    expect(() => assertTransition('recheck', at('attention'))).toThrow(TransitionError);
  });

  it('throws a TransitionError carrying the action and source status', () => {
    try {
      assertTransition('human_close', { ...base, status: 'triaging' });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(TransitionError);
      expect((e as TransitionError).action).toBe('human_close');
      expect((e as TransitionError).from).toBe('triaging');
      expect((e as Error).message).toBe('Cannot human_close a finding that is triaging');
    }
  });
});

describe('decisionWindowStart', () => {
  it('prefers last_triaged_at, then closed_at, then first_seen minus 14 days', () => {
    const f = { ...base, first_seen: '2026-11-20T00:00:00.000Z' };
    expect(decisionWindowStart({ ...f, last_triaged_at: null, closed_at: null })).toBe('2026-11-06T00:00:00.000Z');
    expect(decisionWindowStart({ ...f, last_triaged_at: null, closed_at: '2026-11-22T00:00:00.000Z' })).toBe(
      '2026-11-22T00:00:00.000Z'
    );
    expect(
      decisionWindowStart({
        ...f,
        last_triaged_at: '2026-11-23T00:00:00.000Z',
        closed_at: '2026-11-22T00:00:00.000Z',
      })
    ).toBe('2026-11-23T00:00:00.000Z');
  });
});

describe('isRecheckDue', () => {
  const now = '2026-11-25T12:00:00.000Z';
  const c = (anchor: string, activity: string) => ({
    ...base,
    status: 'closed' as const,
    closed_by: 'ai' as const,
    closed_at: anchor,
    last_triaged_at: anchor,
    last_activity_at: activity,
  });

  it('requires new activity after the anchor AND an anchor older than 24h', () => {
    expect(isRecheckDue(c('2026-11-24T11:00:00.000Z', '2026-11-25T01:00:00.000Z'), now)).toBe(true);
    expect(isRecheckDue(c('2026-11-24T13:00:00.000Z', '2026-11-25T01:00:00.000Z'), now)).toBe(false); // restart re-fire
    expect(isRecheckDue(c('2026-11-20T00:00:00.000Z', '2026-11-20T00:00:00.000Z'), now)).toBe(false); // no new activity
    expect(isRecheckDue({ ...c('2026-11-20T00:00:00.000Z', '2026-11-25T01:00:00.000Z'), status: 'attention' }, now)).toBe(
      false
    );
  });

  it('falls back to closed_at when last_triaged_at is null, and is false with no anchor', () => {
    const f = { ...c('2026-11-20T00:00:00.000Z', '2026-11-25T01:00:00.000Z'), last_triaged_at: null };
    expect(isRecheckDue(f, now)).toBe(true);
    expect(isRecheckDue({ ...f, closed_at: null }, now)).toBe(false);
  });
});

describe('computeSeverityScore', () => {
  it('weights new_client at 1, so a new internal client scores 4', () => {
    const triggers: Trigger[] = [
      { type: 'new_client', first_seen: 't0', last_seen: 't0', active: true },
      { type: 'internal_source', first_seen: 't0', last_seen: 't0', active: true },
    ];
    expect(computeSeverityScore(triggers)).toBe(4);
  });

  it('sums weights of active triggers only', () => {
    const triggers: Trigger[] = [
      { type: 'internal_source', first_seen: 't', last_seen: 't', active: true },
      { type: 'repeat_offender', first_seen: 't', last_seen: 't', active: false },
    ];
    expect(computeSeverityScore(triggers)).toBe(3); // only internal_source (weight 3) is active
    expect(
      computeSeverityScore([
        { type: 'internal_source', first_seen: 't', last_seen: 't', active: true },
        { type: 'repeat_offender', first_seen: 't', last_seen: 't', active: true },
      ])
    ).toBe(5); // 3 + 2
    expect(computeSeverityScore([])).toBe(0);
  });
});
