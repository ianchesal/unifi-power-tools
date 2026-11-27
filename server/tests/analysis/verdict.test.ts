import { describe, expect, it } from 'vitest';
import { validateAiVerdict } from '../../src/analysis/verdict.js';

const ok = { verdict: 'close', risk_level: 'low', summary: 's', reasoning: 'r' } as const;
const ctx = {
  isRecheck: false,
  unblockedIpsAlertsSinceDecision: 0,
  activeEntryIds: new Set<number>(),
  operatorBackedEntryIds: new Set<number>(),
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
      'events DB unavailable; cannot verify every IPS alert was blocked — cite a playbook entry or choose attention'
    );
  });

  // 3 is operator-backed; 4 is active but still shipped default text.
  const entries = {
    activeEntryIds: new Set([3, 4]),
    operatorBackedEntryIds: new Set([3]),
  };

  it('accepts a close with unblocked alerts when it cites an operator-backed entry', () => {
    for (const unblocked of [5, null]) {
      expect(
        validateAiVerdict(
          { ...ok, cited_entries: [4, 3] },
          { ...ctx, ...entries, unblockedIpsAlertsSinceDecision: unblocked }
        )
      ).toBeNull();
    }
  });

  it('rejects a close citing only default entries when unblocked or unverifiable', () => {
    for (const unblocked of [5, null]) {
      expect(
        validateAiVerdict(
          { ...ok, cited_entries: [4] },
          { ...ctx, ...entries, unblockedIpsAlertsSinceDecision: unblocked }
        )
      ).toBe(
        "a shipped default can't by itself justify closing unblocked or unverifiable traffic; cite an operator-written entry or choose attention"
      );
    }
  });

  it('accepts a default citation, or none, when every IPS alert was blocked', () => {
    expect(validateAiVerdict({ ...ok, cited_entries: [4] }, { ...ctx, ...entries })).toBeNull();
    expect(validateAiVerdict(ok, { ...ctx, ...entries })).toBeNull();
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
});
