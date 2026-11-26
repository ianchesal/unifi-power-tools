import type { AiVerdictFields } from '../db/analysisRequestsStore.js';

// Guardrails on an AI verdict, checked before it is recorded. Pure: callers
// supply the sink-derived count and the set of citable playbook entries.

// Narrows the store's AiVerdictFields to what the MCP tool accepts, so a
// validated input can be recorded as-is.
export interface AiVerdictInput extends AiVerdictFields {
  risk_level: 'low' | 'medium' | 'high';
  recommended_action?: string;
  why_now?: string;
}

export interface VerdictContext {
  isRecheck: boolean;
  // null = sink unavailable (no DB, or a query against it failed).
  unblockedIpsAlertsSinceDecision: number | null;
  activeEntryIds: ReadonlySet<number>;
}

// Phase A has no playbook, so nothing is citable yet. Phase C replaces this
// with a playbook_entries lookup.
export const PHASE_A_ACTIVE_ENTRY_IDS: ReadonlySet<number> = new Set();

const isBlank = (s: string | undefined | null) => !s || s.trim() === '';

export function validateAiVerdict(input: AiVerdictInput, ctx: VerdictContext): string | null {
  if (isBlank(input.summary)) return 'summary must not be blank';
  if (isBlank(input.reasoning)) return 'reasoning must not be blank';
  if (input.verdict === 'attention' && isBlank(input.recommended_action)) {
    return 'an attention verdict requires a non-blank recommended_action';
  }
  if (ctx.isRecheck && isBlank(input.why_now)) {
    return 'a recheck verdict requires a non-blank why_now explaining what changed';
  }
  const cited = input.cited_entries ?? [];
  const bad = cited.filter((id) => !ctx.activeEntryIds.has(id));
  if (bad.length > 0) {
    return `cited_entries contains unknown or inactive playbook entries: ${bad.join(', ')}`;
  }
  if (input.verdict === 'close' && cited.length === 0) {
    const unblocked = ctx.unblockedIpsAlertsSinceDecision;
    if (unblocked === null) {
      return 'sink DB unavailable; cannot verify every IPS alert was blocked — cite a playbook entry or choose attention';
    }
    if (unblocked > 0) {
      return `${unblocked} IPS alert(s) since the last decision were not blocked; closing requires a cited playbook entry`;
    }
  }
  return null;
}
