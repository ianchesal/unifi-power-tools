import type { LensDb } from './lensDb.js';

export interface AnalysisRequestRow {
  id: number;
  finding_id: number;
  status: 'pending' | 'answered' | 'cancelled';
  context: string;
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

export function getPendingRequestForFinding(
  db: LensDb,
  findingId: number
): AnalysisRequestRow | null {
  const row = db.conn
    .prepare("SELECT * FROM analysis_requests WHERE finding_id = ? AND status = 'pending'")
    .get(findingId) as AnalysisRequestRow | undefined;
  return row ?? null;
}

// Context is built lazily when the request is fetched (see updateRequestContext),
// so creation stores an empty bundle.
export function createAnalysisRequest(
  db: LensDb,
  findingId: number,
  nowIso: string,
  opts: { isRecheck?: boolean } = {}
): AnalysisRequestRow {
  const existingPending = getPendingRequestForFinding(db, findingId);
  if (existingPending) return existingPending;

  const result = db.conn
    .prepare(
      `INSERT INTO analysis_requests (finding_id, status, context, created_at, is_recheck)
       VALUES (?, 'pending', '{}', ?, ?)`
    )
    .run(findingId, nowIso, opts.isRecheck ? 1 : 0);
  return getAnalysisRequest(db, Number(result.lastInsertRowid)) as AnalysisRequestRow;
}

export function getAnalysisRequest(db: LensDb, id: number): AnalysisRequestRow | null {
  const row = db.conn.prepare('SELECT * FROM analysis_requests WHERE id = ?').get(id) as
    | AnalysisRequestRow
    | undefined;
  return row ?? null;
}

export type PendingAnalysisRow = AnalysisRequestRow & {
  entity_type: string;
  entity_key: string;
  severity_score: number;
};

export function getPendingAnalysisRequests(
  db: LensDb,
  opts: { limit?: number } = {}
): PendingAnalysisRow[] {
  const limit = opts.limit !== undefined ? ' LIMIT ?' : '';
  return db.conn
    .prepare(
      `SELECT r.*, f.entity_type, f.entity_key, f.severity_score
       FROM analysis_requests r JOIN findings f ON f.id = r.finding_id
       WHERE r.status = 'pending'
       ORDER BY f.severity_score DESC, r.created_at ASC, r.id ASC${limit}`
    )
    .all(...(opts.limit !== undefined ? [opts.limit] : [])) as unknown as PendingAnalysisRow[];
}

export function getAnalysisRequestsForFinding(db: LensDb, findingId: number): AnalysisRequestRow[] {
  return db.conn
    .prepare('SELECT * FROM analysis_requests WHERE finding_id = ? ORDER BY created_at ASC')
    .all(findingId) as unknown as AnalysisRequestRow[];
}

export function cancelPendingRequests(db: LensDb, findingId: number): AnalysisRequestRow[] {
  return db.conn
    .prepare(
      "UPDATE analysis_requests SET status = 'cancelled' WHERE finding_id = ? AND status = 'pending' RETURNING *"
    )
    .all(findingId) as unknown as AnalysisRequestRow[];
}

export function updateRequestContext(db: LensDb, id: number, context: object): void {
  db.conn
    .prepare("UPDATE analysis_requests SET context = ? WHERE id = ? AND status = 'pending'")
    .run(JSON.stringify(context), id);
}

export interface AiVerdictFields {
  verdict: 'close' | 'attention';
  risk_level: string;
  summary: string;
  reasoning: string;
  recommended_action?: string | null;
  why_now?: string | null;
  cited_entries?: number[];
}

export function recordAiVerdict(
  db: LensDb,
  id: number,
  v: AiVerdictFields,
  nowIso: string
): AnalysisRequestRow {
  const existing = getAnalysisRequest(db, id);
  if (!existing) throw new Error(`Analysis request ${id} not found`);
  if (existing.status === 'answered') {
    throw new Error(`Analysis request ${id} was already answered`);
  }
  if (existing.status === 'cancelled') {
    throw new Error(`Analysis request ${id} was cancelled (its finding left triaging); skip it`);
  }
  db.conn
    .prepare(
      `UPDATE analysis_requests SET status = 'answered', verdict = ?, risk_level = ?, summary = ?,
         recommendation = ?, recommended_action = ?, why_now = ?, cited_entries = ?, answered_at = ?
       WHERE id = ?`
    )
    .run(
      v.verdict,
      v.risk_level,
      v.summary,
      v.reasoning,
      v.recommended_action ?? null,
      v.why_now ?? null,
      v.cited_entries ? JSON.stringify(v.cited_entries) : null,
      nowIso,
      id
    );
  return getAnalysisRequest(db, id) as AnalysisRequestRow;
}

export function createAnsweredRuleAnalysis(
  db: LensDb,
  findingId: number,
  context: object,
  recommendation: string,
  riskLevel: string,
  now: string
): AnalysisRequestRow {
  const result = db.conn
    .prepare(
      `INSERT INTO analysis_requests (finding_id, status, context, recommendation, summary, verdict, risk_level, source, created_at, answered_at)
       VALUES (?, 'answered', ?, ?, ?, 'close', ?, 'rule', ?, ?)`
    )
    .run(findingId, JSON.stringify(context), recommendation, recommendation, riskLevel, now, now);
  return getAnalysisRequest(db, Number(result.lastInsertRowid)) as AnalysisRequestRow;
}

export function latestAnsweredAnalyses(
  db: LensDb,
  findingIds: number[]
): Map<number, AnalysisRequestRow> {
  const out = new Map<number, AnalysisRequestRow>();
  if (findingIds.length === 0) return out;
  const placeholders = findingIds.map(() => '?').join(', ');
  const rows = db.conn
    .prepare(
      `SELECT * FROM analysis_requests WHERE status = 'answered' AND finding_id IN (${placeholders})
       ORDER BY answered_at ASC, id ASC`
    )
    .all(...findingIds) as unknown as AnalysisRequestRow[];
  for (const r of rows) out.set(r.finding_id, r); // ascending, so the latest wins
  return out;
}

export function getQueueStats(db: LensDb): {
  count: number;
  oldest_created_at: string | null;
  last_answered_at: string | null;
} {
  const pending = db.conn
    .prepare(
      "SELECT COUNT(*) AS count, MIN(created_at) AS oldest FROM analysis_requests WHERE status = 'pending'"
    )
    .get() as { count: number; oldest: string | null };
  const answered = db.conn
    .prepare(
      "SELECT MAX(answered_at) AS last FROM analysis_requests WHERE source = 'ai' AND status = 'answered'"
    )
    .get() as { last: string | null };
  return {
    count: pending.count,
    oldest_created_at: pending.oldest,
    last_answered_at: answered.last,
  };
}
