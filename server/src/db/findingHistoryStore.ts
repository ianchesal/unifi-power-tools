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

// The operator's own decisions: the signals playbook proposals are made from.
const FEEDBACK_KINDS: HistoryKind[] = [
  'human_closed_handled',
  'human_closed_not_concern',
  'human_reopened',
];
const FEEDBACK_KINDS_SQL = FEEDBACK_KINDS.map((k) => `'${k}'`).join(', ');

export type FeedbackRow = FindingHistoryRow & {
  entity_type: string;
  entity_key: string;
  status: string;
};

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

// The note of each finding's most recent human_reopened row, in one query.
// Findings never reopened are absent from the map.
export function latestReopenNotes(db: LensDb, findingIds: number[]): Map<number, string | null> {
  const out = new Map<number, string | null>();
  if (findingIds.length === 0) return out;
  const placeholders = findingIds.map(() => '?').join(', ');
  const rows = db.conn
    .prepare(
      `SELECT finding_id, note FROM (
         SELECT finding_id, note, ROW_NUMBER() OVER (
           PARTITION BY finding_id ORDER BY at DESC, id DESC
         ) AS rn
         FROM finding_history
         WHERE kind = 'human_reopened' AND finding_id IN (${placeholders})
       ) WHERE rn = 1`
    )
    .all(...findingIds) as { finding_id: number; note: string | null }[];
  for (const r of rows) out.set(r.finding_id, r.note);
  return out;
}

// Operator decisions no triage run has reviewed yet, oldest first.
export function pendingFeedback(db: LensDb, limit: number): FeedbackRow[] {
  return db.conn
    .prepare(
      `SELECT h.*, f.entity_type, f.entity_key, f.status
       FROM finding_history h JOIN findings f ON f.id = h.finding_id
       WHERE h.kind IN (${FEEDBACK_KINDS_SQL}) AND h.feedback_considered_at IS NULL
       ORDER BY h.at ASC, h.id ASC LIMIT ?`
    )
    .all(limit) as unknown as FeedbackRow[];
}

// Returns how many rows were newly marked; other ids are ignored.
export function markFeedbackConsidered(db: LensDb, ids: number[], nowIso: string): number {
  if (ids.length === 0) return 0;
  const placeholders = ids.map(() => '?').join(', ');
  const result = db.conn
    .prepare(
      `UPDATE finding_history SET feedback_considered_at = ?
       WHERE id IN (${placeholders})
         AND kind IN (${FEEDBACK_KINDS_SQL}) AND feedback_considered_at IS NULL`
    )
    .run(nowIso, ...ids);
  return Number(result.changes);
}
