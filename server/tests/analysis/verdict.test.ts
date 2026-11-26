import { describe, expect, it } from 'vitest';
import { PHASE_A_ACTIVE_ENTRY_IDS, validateAiVerdict } from '../../src/analysis/verdict.js';

const ok = { verdict: 'close', risk_level: 'low', summary: 's', reasoning: 'r' } as const;
const ctx = {
  isRecheck: false,
  unblockedIpsAlertsSinceDecision: 0,
  activeEntryIds: new Set<number>(),
};

describe('validateAiVerdict', () => {
  it('accepts a close when every IPS alert was blocked', () => {
    expect(validateAiVerdict(ok, ctx)).toBeNull();
  });

  it('rejects a close with unblocked IPS alerts and no citation', () => {
    expect(validateAiVerdict(ok, { ...ctx, unblockedIpsAlertsSinceDecision: 2 })).toBe(
      '2 IPS alert(s) since the last decision were not blocked; closing requires a cited playbook entry'
    );
  });

  it('rejects a close without citations when the sink is unavailable', () => {
    expect(validateAiVerdict(ok, { ...ctx, unblockedIpsAlertsSinceDecision: null })).toBe(
      'sink DB unavailable; cannot verify every IPS alert was blocked — cite a playbook entry or choose attention'
    );
  });

  it('accepts a close with unblocked alerts when it cites an active entry', () => {
    expect(
      validateAiVerdict(
        { ...ok, cited_entries: [3] },
        { ...ctx, unblockedIpsAlertsSinceDecision: 5, activeEntryIds: new Set([3]) }
      )
    ).toBeNull();
  });

  it('accepts attention regardless of unblocked alerts or a missing sink', () => {
    const attention = { ...ok, verdict: 'attention', recommended_action: 'look' } as const;
    expect(validateAiVerdict(attention, { ...ctx, unblockedIpsAlertsSinceDecision: null })).toBeNull();
    expect(validateAiVerdict(attention, { ...ctx, unblockedIpsAlertsSinceDecision: 4 })).toBeNull();
  });

  it('rejects unknown or inactive cited entries', () => {
    const msg = validateAiVerdict(
      { ...ok, cited_entries: [7, 3, 9] },
      { ...ctx, activeEntryIds: new Set([3]) }
    );
    expect(msg).toMatch(/7, 9/);
    expect(msg).not.toMatch(/3/);
  });

  it('attention requires a non-blank recommended_action', () => {
    expect(
      validateAiVerdict({ ...ok, verdict: 'attention', recommended_action: '  ' }, ctx)
    ).toMatch(/recommended_action/);
    expect(validateAiVerdict({ ...ok, verdict: 'attention' }, ctx)).toMatch(/recommended_action/);
  });

  it('a recheck requires a non-blank why_now', () => {
    expect(validateAiVerdict(ok, { ...ctx, isRecheck: true })).toMatch(/why_now/);
    expect(validateAiVerdict({ ...ok, why_now: ' ' }, { ...ctx, isRecheck: true })).toMatch(
      /why_now/
    );
    expect(validateAiVerdict({ ...ok, why_now: 'new burst' }, { ...ctx, isRecheck: true })).toBeNull();
  });

  it('blank summary or reasoning is rejected', () => {
    expect(validateAiVerdict({ ...ok, summary: '   ' }, ctx)).toMatch(/summary/);
    expect(validateAiVerdict({ ...ok, reasoning: '' }, ctx)).toMatch(/reasoning/);
  });

  it('checks run in order: blank summary is reported before the IPS guardrail', () => {
    expect(
      validateAiVerdict({ ...ok, summary: '' }, { ...ctx, unblockedIpsAlertsSinceDecision: 3 })
    ).toMatch(/summary/);
  });

  it('phase A has no active playbook entries', () => {
    expect(PHASE_A_ACTIVE_ENTRY_IDS.size).toBe(0);
  });
});
