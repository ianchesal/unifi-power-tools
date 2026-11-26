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
// Every way a finding gets (or stays) closed: what a reopen can be undoing.
const CLOSE_KINDS: HistoryKind[] = [
  'rule_closed',
  'recheck_rule_still_closed',
  'ai_closed',
  'human_closed_handled',
  'human_closed_not_concern',
];
const sqlList = (kinds: HistoryKind[]) => kinds.map((k) => `'${k}'`).join(', ');
const FEEDBACK_KINDS_SQL = sqlList(FEEDBACK_KINDS);

export type FeedbackRow = FindingHistoryRow & {
  entity_type: string;
  entity_key: string;
  status: string;
  // On a human_reopened row, the close it undid; a rule's summary names the rule.
  // null on other rows, and when no earlier close is on record.
  reopened_from: { kind: HistoryKind; summary: string } | null;
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
  const rows = db.conn
    .prepare(
      `SELECT h.*, f.entity_type, f.entity_key, f.status,
              c.kind AS closed_kind, c.summary AS closed_summary
       FROM finding_history h
       JOIN findings f ON f.id = h.finding_id
       LEFT JOIN finding_history c ON c.id = (
         SELECT MAX(p.id) FROM finding_history p
         WHERE h.kind = 'human_reopened' AND p.finding_id = h.finding_id AND p.id < h.id
           AND p.kind IN (${sqlList(CLOSE_KINDS)})
       )
       WHERE h.kind IN (${FEEDBACK_KINDS_SQL}) AND h.feedback_considered_at IS NULL
       ORDER BY h.at ASC, h.id ASC LIMIT ?`
    )
    .all(limit) as unknown as (Omit<FeedbackRow, 'reopened_from'> & {
    closed_kind: HistoryKind | null;
    closed_summary: string | null;
  })[];
  return rows.map(({ closed_kind, closed_summary, ...row }) => ({
    ...row,
    reopened_from:
      closed_kind === null ? null : { kind: closed_kind, summary: closed_summary as string },
  }));
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
