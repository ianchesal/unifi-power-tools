export type EntityType = 'signature' | 'source_ip' | 'client';
export type FindingStatus = 'triaging' | 'attention' | 'closed';
export type ClosedBy = 'rule' | 'ai' | 'human' | 'system';

export interface Trigger {
  type: 'anomaly' | 'repeat_offender' | 'new_signature' | 'new_source_ip' | 'new_client' | 'internal_source';
  first_seen: string;
  last_seen: string;
  active: boolean;
}

// Mirrors the server's AnalysisRequestRow minus the `context` bundle, which
// the API never sends to the dashboard.
export interface AnalysisRequest {
  id: number;
  finding_id: number;
  status: 'pending' | 'answered' | 'cancelled';
  recommendation: string | null;
  risk_level: string | null;
  source: 'ai' | 'rule';
  created_at: string;
  answered_at: string | null;
  verdict: 'close' | 'attention' | null;
  summary: string | null;
  recommended_action: string | null;
  why_now: string | null;
  cited_entries: string | null; // JSON number[]
  is_recheck: number; // 0 | 1
}

export interface Finding {
  id: number;
  entity_type: EntityType;
  entity_key: string;
  // Client findings only: latest known client name for the MAC (null if unknown).
  display_name?: string | null;
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
  latest_analysis: AnalysisRequest | null;
}

export type HistoryKind =
  | 'created'
  | 'trigger_added'
  | 'rule_closed'
  | 'queued'
  | 'ai_closed'
  | 'ai_attention'
  | 'human_closed_handled'
  | 'human_closed_not_concern'
  | 'human_reopened'
  | 'human_reanalyze'
  | 'recheck_rule_still_closed'
  | 'recheck_queued'
  | 'request_cancelled';

export interface HistoryEntry {
  id: number;
  finding_id: number;
  at: string;
  kind: HistoryKind;
  actor: ClosedBy;
  summary: string;
  note: string | null;
  analysis_request_id: number | null;
  feedback_considered_at: string | null;
}

export interface QueueStats {
  count: number;
  oldest_created_at: string | null;
  last_answered_at: string | null;
}

export interface FindingsSummary {
  attention: number;
  triaging: number;
  closed_last_7d: Record<ClosedBy, number>;
}

// A pending row from GET /api/analysis-requests (joined with its finding).
export interface PendingAnalysis extends AnalysisRequest {
  entity_type: EntityType;
  entity_key: string;
  severity_score: number;
}
