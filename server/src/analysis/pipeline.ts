import {
  type AnalysisRequestRow,
  cancelPendingRequests,
  createAnalysisRequest,
  createAnsweredRuleAnalysis,
} from '../db/analysisRequestsStore.js';
import { addHistory } from '../db/findingHistoryStore.js';
import { type FindingStatePatch, getFindingById, updateFindingState } from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';
import { assertTransition, type Finding, FindingNotFoundError } from './findings.js';
import type { RuleMatch } from './matchRules.js';

// The single place finding status transitions happen. Every function asserts the
// transition is legal, updates the finding, cancels any pending analysis request
// when the finding leaves `triaging`, and writes the history rows — all in one
// SQLite transaction so a failure can't leave a half-applied transition.

const CLOSE_CLEARED: FindingStatePatch = {
  closed_by: null,
  closed_reason: null,
  closed_at: null,
};

// Re-entrant: when the caller already holds a transaction, join it and let the
// outermost owner commit or roll back.
export function atomically<T>(db: LensDb, fn: () => T): T {
  if (db.conn.isTransaction) return fn();
  db.conn.exec('BEGIN');
  try {
    const out = fn();
    db.conn.exec('COMMIT');
    return out;
  } catch (err) {
    try {
      db.conn.exec('ROLLBACK');
    } catch {
      // SQLite may already have rolled back; surface the original error.
    }
    throw err;
  }
}

// Fresh read for assertions made inside a transaction, so a stale caller copy
// can't authorise a transition or lose a counter increment.
function reload(db: LensDb, finding: Finding): Finding {
  return loadFinding(db, finding.id as number);
}

function loadFinding(db: LensDb, id: number): Finding {
  const finding = getFindingById(db, id);
  if (!finding) throw new FindingNotFoundError();
  return finding;
}

function apply(db: LensDb, finding: Finding, patch: FindingStatePatch): Finding {
  const updated = updateFindingState(db, finding.id as number, patch);
  if (!updated) throw new FindingNotFoundError();
  return updated;
}

// Leaving `triaging` makes any queued analysis moot; record each cancellation.
function cancelPending(db: LensDb, finding: Finding, nowIso: string): void {
  if (finding.status !== 'triaging') return;
  for (const req of cancelPendingRequests(db, finding.id as number)) {
    addHistory(db, {
      finding_id: finding.id as number,
      at: nowIso,
      kind: 'request_cancelled',
      actor: 'system',
      summary: 'Pending analysis request cancelled',
      analysis_request_id: req.id,
    });
  }
}

export function recordCreated(db: LensDb, finding: Finding, nowIso: string): void {
  const triggers = finding.triggers.map((t) => t.type).join(', ');
  addHistory(db, {
    finding_id: finding.id as number,
    at: nowIso,
    kind: 'created',
    actor: 'system',
    summary: `Finding created (${triggers})`,
  });
}

export function queueForAnalysis(db: LensDb, finding: Finding, nowIso: string): AnalysisRequestRow {
  if (finding.status !== 'triaging') {
    throw new Error(`Cannot queue a finding that is ${finding.status}; it must be triaging`);
  }
  return atomically(db, () => {
    const req = createAnalysisRequest(db, finding.id as number, nowIso);
    addHistory(db, {
      finding_id: finding.id as number,
      at: nowIso,
      kind: 'queued',
      actor: 'system',
      summary: 'Queued for analysis',
      analysis_request_id: req.id,
    });
    return req;
  });
}

export function closeByRule(
  db: LensDb,
  finding: Finding,
  match: RuleMatch,
  nowIso: string
): Finding {
  return atomically(db, () => {
    const current = reload(db, finding);
    assertTransition('rule_close', current);
    cancelPending(db, current, nowIso);
    const analysis = createAnsweredRuleAnalysis(
      db,
      finding.id as number,
      { finding: current, rule: match.rule },
      match.verdict.recommendation,
      match.verdict.riskLevel,
      nowIso
    );
    const updated = apply(db, current, {
      status: 'closed',
      closed_by: 'rule',
      closed_reason: match.verdict.recommendation,
      closed_at: nowIso,
      last_triaged_at: nowIso,
    });
    addHistory(db, {
      finding_id: finding.id as number,
      at: nowIso,
      kind: 'rule_closed',
      actor: 'rule',
      summary: `Closed by rule ${match.rule}`,
      analysis_request_id: analysis.id,
    });
    return updated;
  });
}

export function recheckStillClosed(
  db: LensDb,
  finding: Finding,
  match: RuleMatch,
  nowIso: string
): Finding {
  return atomically(db, () => {
    const current = reload(db, finding);
    assertTransition('recheck', current);
    const updated = apply(db, current, { last_triaged_at: nowIso });
    addHistory(db, {
      finding_id: finding.id as number,
      at: nowIso,
      kind: 'recheck_rule_still_closed',
      actor: 'rule',
      summary: `Recheck: rule ${match.rule} still closes this finding`,
    });
    return updated;
  });
}

export function recheckRequeue(db: LensDb, finding: Finding, nowIso: string): Finding {
  return atomically(db, () => {
    const current = reload(db, finding);
    assertTransition('recheck', current);
    const updated = apply(db, current, {
      ...CLOSE_CLEARED,
      status: 'triaging',
      reopen_count: current.reopen_count + 1,
    });
    const req = createAnalysisRequest(db, finding.id as number, nowIso, { isRecheck: true });
    addHistory(db, {
      finding_id: finding.id as number,
      at: nowIso,
      kind: 'recheck_queued',
      actor: 'system',
      summary: 'New activity since last decision; queued for re-analysis',
      analysis_request_id: req.id,
    });
    return updated;
  });
}

export function humanClose(
  db: LensDb,
  findingId: number,
  kind: 'handled' | 'not_concern',
  note: string | null,
  nowIso: string
): Finding {
  const finding = loadFinding(db, findingId);
  assertTransition('human_close', finding);
  const cleanNote = note?.trim() || null;
  return atomically(db, () => {
    cancelPending(db, finding, nowIso);
    const updated = apply(db, finding, {
      status: 'closed',
      closed_by: 'human',
      closed_reason: cleanNote ?? (kind === 'handled' ? 'Handled' : 'Not a concern'),
      closed_at: nowIso,
      last_triaged_at: nowIso,
    });
    addHistory(db, {
      finding_id: findingId,
      at: nowIso,
      kind: kind === 'handled' ? 'human_closed_handled' : 'human_closed_not_concern',
      actor: 'human',
      summary: kind === 'handled' ? 'Closed as handled' : 'Closed as not a concern',
      note: cleanNote,
    });
    return updated;
  });
}

export function humanReopen(db: LensDb, findingId: number, note: string, nowIso: string): Finding {
  const cleanNote = note.trim();
  if (cleanNote === '') throw new Error('note is required');
  const finding = loadFinding(db, findingId);
  assertTransition('human_reopen', finding);
  return atomically(db, () => {
    cancelPending(db, finding, nowIso);
    const updated = apply(db, finding, {
      ...CLOSE_CLEARED,
      status: 'attention',
      last_triaged_at: nowIso,
    });
    addHistory(db, {
      finding_id: findingId,
      at: nowIso,
      kind: 'human_reopened',
      actor: 'human',
      summary: 'Reopened for attention',
      note: cleanNote,
    });
    return updated;
  });
}

export function reanalyze(db: LensDb, findingId: number, nowIso: string): Finding {
  const finding = loadFinding(db, findingId);
  assertTransition('reanalyze', finding);
  return atomically(db, () => {
    const updated = apply(db, finding, { ...CLOSE_CLEARED, status: 'triaging' });
    const req = createAnalysisRequest(db, findingId, nowIso);
    addHistory(db, {
      finding_id: findingId,
      at: nowIso,
      kind: 'human_reanalyze',
      actor: 'human',
      summary: 'Re-analysis requested',
      analysis_request_id: req.id,
    });
    return updated;
  });
}
