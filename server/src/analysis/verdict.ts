import type { AiVerdictFields } from '../db/analysisRequestsStore.js';

// Guardrails on an AI verdict, checked before it is recorded. Pure: callers
// supply the events-derived count and the sets of citable playbook entries.

// Narrows the store's AiVerdictFields to what the MCP tool accepts, so a
// validated input can be recorded as-is.
export interface AiVerdictInput extends AiVerdictFields {
  risk_level: 'low' | 'medium' | 'high';
  recommended_action?: string;
  why_now?: string;
}

export interface VerdictContext {
  isRecheck: boolean;
  // null = the events query failed.
  unblockedIpsAlertsSinceDecision: number | null;
  activeEntryIds: ReadonlySet<number>;
  // The active entries whose current text the operator wrote or approved, as
  // opposed to shipped default text.
  operatorBackedEntryIds: ReadonlySet<number>;
}

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
  if (input.verdict !== 'close') return null;

  // Closing unblocked or unverifiable traffic takes an entry the operator stands
  // behind: shipped default text names no host, so it can't justify it alone.
  const unblocked = ctx.unblockedIpsAlertsSinceDecision;
  if (unblocked === 0) return null;
  if (cited.length === 0) {
    return unblocked === null
      ? 'events DB unavailable; cannot verify every IPS alert was blocked — cite a playbook entry or choose attention'
      : `${unblocked} IPS alert(s) since the last decision were not blocked; closing requires a cited playbook entry`;
  }
  if (!cited.some((id) => ctx.operatorBackedEntryIds.has(id))) {
    return "a shipped default can't by itself justify closing unblocked or unverifiable traffic; cite an operator-written entry or choose attention";
  }
  return null;
}
