import type { LensDb } from './lensDb.js';

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

export type Actor = 'rule' | 'ai' | 'human' | 'system';

export interface FindingHistoryRow {
  id: number;
  finding_id: number;
  at: string;
  kind: HistoryKind;
  actor: Actor;
  summary: string;
  note: string | null;
  analysis_request_id: number | null;
  feedback_considered_at: string | null;
}

export function addHistory(
  db: LensDb,
  e: {
    finding_id: number;
    at: string;
    kind: HistoryKind;
    actor: Actor;
    summary: string;
    note?: string | null;
    analysis_request_id?: number | null;
  }
): FindingHistoryRow {
  return db.conn
    .prepare(
      `INSERT INTO finding_history (finding_id, at, kind, actor, summary, note, analysis_request_id)
       VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`
    )
    .get(
      e.finding_id,
      e.at,
      e.kind,
      e.actor,
      e.summary,
      e.note ?? null,
      e.analysis_request_id ?? null
    ) as unknown as FindingHistoryRow;
}

export function listHistory(db: LensDb, findingId: number): FindingHistoryRow[] {
  return db.conn
    .prepare('SELECT * FROM finding_history WHERE finding_id = ? ORDER BY at ASC, id ASC')
    .all(findingId) as unknown as FindingHistoryRow[];
}
