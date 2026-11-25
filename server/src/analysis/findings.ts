export type TriggerType =
  | 'anomaly'
  | 'repeat_offender'
  | 'new_signature'
  | 'new_source_ip'
  | 'new_client'
  | 'internal_source';

// Only these two triggers represent an ongoing condition that can lift; a
// first-seen event (signature, IP or client) or an IP's internal-ness can't
// "un-happen". Lifting only flips `active` (and the severity score) — it never
// changes a finding's status.
export const STANDING_TRIGGER_TYPES: TriggerType[] = ['anomaly', 'repeat_offender'];

export interface Trigger {
  type: TriggerType;
  first_seen: string;
  last_seen: string;
  active: boolean;
}

export type FindingStatus = 'triaging' | 'attention' | 'closed';
export type ClosedBy = 'rule' | 'ai' | 'human' | 'system';

export interface Finding {
  id?: number;
  entity_type: 'signature' | 'source_ip' | 'client';
  entity_key: string;
  first_seen: string;
  last_seen: string;
  triggers: Trigger[];
  severity_score: number;
  status: FindingStatus;
  closed_by: ClosedBy | null;
  closed_reason: string | null;
  closed_at: string | null;
  last_activity_at: string;
  last_triaged_at: string | null;
  reopen_count: number;
}

const TRIGGER_WEIGHTS: Record<TriggerType, number> = {
  anomaly: 3,
  repeat_offender: 2,
  new_signature: 2,
  new_source_ip: 1,
  new_client: 1,
  internal_source: 3,
};

export function computeSeverityScore(triggers: Trigger[]): number {
  return triggers.filter((t) => t.active).reduce((sum, t) => sum + TRIGGER_WEIGHTS[t.type], 0);
}

export function applyTrigger(
  existing: Finding | null,
  type: TriggerType,
  now: string,
  entityType: Finding['entity_type'],
  entityKey: string
): Finding {
  if (!existing) {
    const triggers: Trigger[] = [{ type, first_seen: now, last_seen: now, active: true }];
    return {
      entity_type: entityType,
      entity_key: entityKey,
      first_seen: now,
      last_seen: now,
      triggers,
      severity_score: computeSeverityScore(triggers),
      status: 'triaging',
      closed_by: null,
      closed_reason: null,
      closed_at: null,
      last_activity_at: now,
      last_triaged_at: null,
      reopen_count: 0,
    };
  }

  const hasType = existing.triggers.some((t) => t.type === type);
  const triggers: Trigger[] = hasType
    ? existing.triggers.map((t) => (t.type === type ? { ...t, active: true, last_seen: now } : t))
    : [...existing.triggers, { type, first_seen: now, last_seen: now, active: true }];

  // Status is untouched, with one exception: a rule-closed finding that gains
  // internal_source goes back to triaging. Being on the LAN voids the "noise"
  // verdict a rule reached without that context.
  const reopenForInternal =
    !hasType &&
    type === 'internal_source' &&
    existing.status === 'closed' &&
    existing.closed_by === 'rule';

  return {
    ...existing,
    last_seen: now,
    triggers,
    severity_score: computeSeverityScore(triggers),
    ...(reopenForInternal
      ? { status: 'triaging' as const, closed_by: null, closed_reason: null, closed_at: null }
      : {}),
  };
}

export function reevaluateTrigger(
  finding: Finding,
  type: TriggerType,
  active: boolean,
  now: string
): Finding {
  if (!finding.triggers.some((t) => t.type === type)) {
    return finding;
  }

  const triggers = finding.triggers.map((t) =>
    t.type === type ? { ...t, active, last_seen: active ? now : t.last_seen } : t
  );

  return {
    ...finding,
    triggers,
    severity_score: computeSeverityScore(triggers),
    last_seen: active ? now : finding.last_seen,
  };
}

export type TransitionAction =
  | 'rule_close'
  | 'submit_analysis'
  | 'recheck'
  | 'human_close'
  | 'human_reopen'
  | 'reanalyze';

export class TransitionError extends Error {
  constructor(
    public readonly action: TransitionAction,
    public readonly from: FindingStatus
  ) {
    super(`Cannot ${action} a finding that is ${from}`);
    this.name = 'TransitionError';
  }
}

export class FindingNotFoundError extends Error {
  constructor(message = 'Finding not found') {
    super(message);
    this.name = 'FindingNotFoundError';
  }
}

const ALLOWED: Record<TransitionAction, (f: Finding) => boolean> = {
  rule_close: (f) => f.status === 'triaging',
  submit_analysis: (f) => f.status === 'triaging',
  recheck: (f) => f.status === 'closed',
  human_close: (f) => f.status === 'attention',
  human_reopen: (f) => f.status === 'closed',
  reanalyze: (f) => f.status === 'closed' || f.status === 'attention',
};

export function assertTransition(action: TransitionAction, finding: Finding): void {
  if (!ALLOWED[action](finding)) throw new TransitionError(action, finding.status);
}

// Repeat-offender is the widest creation window (14 days), so a never-decided
// finding's evidence can reach back that far before first_seen.
export const NEVER_DECIDED_LOOKBACK_DAYS = 14;
export const RECHECK_MIN_INTERVAL_HOURS = 24;

const DAY_MS = 24 * 60 * 60 * 1000;

export function decisionWindowStart(finding: Finding): string {
  return (
    finding.last_triaged_at ??
    finding.closed_at ??
    new Date(Date.parse(finding.first_seen) - NEVER_DECIDED_LOOKBACK_DAYS * DAY_MS).toISOString()
  );
}

export function isRecheckDue(finding: Finding, nowIso: string): boolean {
  if (finding.status !== 'closed') return false;
  const anchor = finding.last_triaged_at ?? finding.closed_at;
  if (anchor === null) return false;
  return (
    finding.last_activity_at > anchor &&
    Date.parse(anchor) < Date.parse(nowIso) - RECHECK_MIN_INTERVAL_HOURS * 60 * 60 * 1000
  );
}
