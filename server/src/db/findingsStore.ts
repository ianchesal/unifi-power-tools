import type { ClosedBy, Finding, FindingStatus } from '../analysis/findings.js';
import type { LensDb } from './lensDb.js';

interface FindingRow {
  id: number;
  entity_type: string;
  entity_key: string;
  first_seen: string;
  last_seen: string;
  triggers: string;
  severity_score: number;
  status: string;
  closed_by: string | null;
  closed_reason: string | null;
  closed_at: string | null;
  last_activity_at: string;
  last_triaged_at: string | null;
  reopen_count: number;
}

function rowToFinding(row: FindingRow): Finding {
  return {
    id: row.id,
    entity_type: row.entity_type as Finding['entity_type'],
    entity_key: row.entity_key,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    triggers: JSON.parse(row.triggers),
    severity_score: row.severity_score,
    status: row.status as FindingStatus,
    closed_by: row.closed_by as ClosedBy | null,
    closed_reason: row.closed_reason,
    closed_at: row.closed_at,
    last_activity_at: row.last_activity_at,
    last_triaged_at: row.last_triaged_at,
    reopen_count: row.reopen_count,
  };
}

export function getFinding(
  db: LensDb,
  entityType: Finding['entity_type'],
  entityKey: string
): Finding | null {
  const row = db.conn
    .prepare('SELECT * FROM findings WHERE entity_type = ? AND entity_key = ?')
    .get(entityType, entityKey) as FindingRow | undefined;
  return row ? rowToFinding(row) : null;
}

export function getFindingById(db: LensDb, id: number): Finding | null {
  const row = db.conn.prepare('SELECT * FROM findings WHERE id = ?').get(id) as
    | FindingRow
    | undefined;
  return row ? rowToFinding(row) : null;
}

// last_activity_at, last_triaged_at and reopen_count are deliberately absent from
// the conflict update: they're owned by bumpLastActivity / updateFindingState, so a
// re-detection upsert can't clobber them.
export function upsertFinding(db: LensDb, finding: Finding): Finding {
  const triggersJson = JSON.stringify(finding.triggers);
  db.conn
    .prepare(
      `INSERT INTO findings (entity_type, entity_key, first_seen, last_seen, triggers, severity_score, status,
                             closed_by, closed_reason, closed_at, last_activity_at, last_triaged_at, reopen_count)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(entity_type, entity_key) DO UPDATE SET
         last_seen = excluded.last_seen,
         triggers = excluded.triggers,
         severity_score = excluded.severity_score,
         status = excluded.status,
         closed_by = excluded.closed_by,
         closed_reason = excluded.closed_reason,
         closed_at = excluded.closed_at`
    )
    .run(
      finding.entity_type,
      finding.entity_key,
      finding.first_seen,
      finding.last_seen,
      triggersJson,
      finding.severity_score,
      finding.status,
      finding.closed_by,
      finding.closed_reason,
      finding.closed_at,
      finding.last_activity_at,
      finding.last_triaged_at,
      finding.reopen_count
    );
  return getFinding(db, finding.entity_type, finding.entity_key) as Finding;
}

export type FindingStatePatch = Partial<
  Pick<
    Finding,
    'status' | 'closed_by' | 'closed_reason' | 'closed_at' | 'last_triaged_at' | 'reopen_count'
  >
>;

const STATE_PATCH_COLUMNS = [
  'status',
  'closed_by',
  'closed_reason',
  'closed_at',
  'last_triaged_at',
  'reopen_count',
] as const;

export function updateFindingState(
  db: LensDb,
  id: number,
  patch: FindingStatePatch
): Finding | null {
  const cols = STATE_PATCH_COLUMNS.filter((c) => patch[c] !== undefined);
  if (cols.length === 0) return getFindingById(db, id);
  const row = db.conn
    .prepare(
      `UPDATE findings SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ? RETURNING *`
    )
    .get(...cols.map((c) => patch[c] as string | number | null), id) as FindingRow | undefined;
  return row ? rowToFinding(row) : null;
}

export type FindingsView = 'open' | 'attention' | 'triaging' | 'closed' | 'all';

export interface FindingsFilter {
  view?: FindingsView;
  closedBy?: ClosedBy;
  q?: string;
}

function findingsWhereClause(opts: FindingsFilter): { where: string; params: string[] } {
  const clauses: string[] = [];
  const params: string[] = [];
  const view = opts.view ?? 'open';
  if (view === 'open') clauses.push("status IN ('attention', 'triaging')");
  else if (view !== 'all') {
    clauses.push('status = ?');
    params.push(view);
  }
  if (opts.closedBy) {
    clauses.push('closed_by = ?');
    params.push(opts.closedBy);
  }
  if (opts.q) {
    const like = `%${opts.q.replace(/[\\%_]/g, '\\$&')}%`;
    clauses.push(
      "(entity_key LIKE ? ESCAPE '\\' COLLATE NOCASE OR closed_reason LIKE ? ESCAPE '\\' COLLATE NOCASE)"
    );
    params.push(like, like);
  }
  return { where: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '', params };
}

export function listFindings(
  db: LensDb,
  opts: FindingsFilter & { limit?: number; offset?: number } = {}
): Finding[] {
  const { where, params } = findingsWhereClause(opts);
  const order =
    opts.view === 'closed' ? 'closed_at DESC, id DESC' : 'severity_score DESC, first_seen ASC';
  const pagination = opts.limit !== undefined ? ' LIMIT ? OFFSET ?' : '';
  const rows = db.conn
    .prepare(`SELECT * FROM findings ${where} ORDER BY ${order}${pagination}`)
    .all(
      ...params,
      ...(opts.limit !== undefined ? [opts.limit, opts.offset ?? 0] : [])
    ) as unknown as FindingRow[];
  return rows.map(rowToFinding);
}

export function countFindings(db: LensDb, opts: FindingsFilter = {}): number {
  const { where, params } = findingsWhereClause(opts);
  const row = db.conn.prepare(`SELECT COUNT(*) as count FROM findings ${where}`).get(...params) as {
    count: number;
  };
  return row.count;
}

export function bumpLastActivity(
  db: LensDb,
  entityType: Finding['entity_type'],
  entityKey: string,
  atIso: string
): void {
  db.conn
    .prepare(
      `UPDATE findings SET last_activity_at = ?
       WHERE entity_type = ? AND entity_key = ? AND last_activity_at < ?`
    )
    .run(atIso, entityType, entityKey, atIso);
}

export function closedCountsSince(db: LensDb, sinceIso: string): Record<ClosedBy, number> {
  const counts: Record<ClosedBy, number> = { rule: 0, ai: 0, human: 0, system: 0 };
  const rows = db.conn
    .prepare(
      `SELECT closed_by, COUNT(*) AS count FROM findings
       WHERE status = 'closed' AND closed_at >= ? AND closed_by IS NOT NULL
       GROUP BY closed_by`
    )
    .all(sinceIso) as { closed_by: ClosedBy; count: number }[];
  for (const r of rows) if (r.closed_by in counts) counts[r.closed_by] = r.count;
  return counts;
}

export function hasSeenSignature(db: LensDb, category: string, signature: string): boolean {
  const row = db.conn
    .prepare('SELECT 1 FROM seen_signatures WHERE category = ? AND signature = ?')
    .get(category, signature);
  return row !== undefined;
}

export function markSeenSignature(
  db: LensDb,
  category: string,
  signature: string,
  now: string
): void {
  db.conn
    .prepare(
      'INSERT OR IGNORE INTO seen_signatures (category, signature, first_seen) VALUES (?, ?, ?)'
    )
    .run(category, signature, now);
}

export function hasSeenSourceIp(db: LensDb, sourceIp: string): boolean {
  const row = db.conn.prepare('SELECT 1 FROM seen_source_ips WHERE source_ip = ?').get(sourceIp);
  return row !== undefined;
}

export function markSeenSourceIp(db: LensDb, sourceIp: string, now: string): void {
  db.conn
    .prepare('INSERT OR IGNORE INTO seen_source_ips (source_ip, first_seen) VALUES (?, ?)')
    .run(sourceIp, now);
}

export function seenClientMacs(db: LensDb): Set<string> {
  const rows = db.conn.prepare('SELECT mac FROM seen_clients').all() as { mac: string }[];
  return new Set(rows.map((r) => r.mac));
}

export function markSeenClient(db: LensDb, mac: string, now: string): void {
  db.conn
    .prepare('INSERT OR IGNORE INTO seen_clients (mac, first_seen) VALUES (?, ?)')
    .run(mac, now);
}
