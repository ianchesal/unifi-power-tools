import { decisionWindowStart, type Finding } from '../analysis/findings.js';
import { splitSignatureKey } from '../analysis/newEntity.js';
import { NEW_ENTITY_WINDOW_HOURS } from '../analysis/runner.js';
import { type FindingWithDisplayName, withDisplayNames } from '../api/findings.js';
import {
  type AnalysisRequestRow,
  getAnalysisRequestsForFinding,
} from '../db/analysisRequestsStore.js';
import {
  type ActivitySummary,
  countUnblockedIpsAlerts,
  entityActivitySummary,
  eventsForClientMac,
  eventsForSignature,
  eventsForSourceIp,
  type StoredEvent,
} from '../db/eventQueries.js';
import type { EventsDb } from '../db/eventsDb.js';
import { type FindingHistoryRow, listHistory } from '../db/findingHistoryStore.js';
import type { LensDb } from '../db/lensDb.js';
import {
  annotateHomelabDestinations,
  type HomelabRegistry,
  type lookupHomelabService,
} from '../enrichment/homelabServices.js';
import type { UnifiMcpClient } from '../enrichment/unifiMcpClient.js';

// The bundle a Claude Code session reasons over, built when the request is
// fetched (not when it is queued) so it reflects the sink as it is now.

const RECENT_EVENTS_LIMIT = 20;
const BASELINE_HISTORY_LIMIT = 14;
const RECHECK_BEFORE_DAYS = 14;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface AnalysisDeps {
  lensDb: LensDb;
  eventsDb: EventsDb;
  unifiMcp: UnifiMcpClient;
  homelabServices: HomelabRegistry;
}

interface BaselineRow {
  day: string;
  count: number;
}

export interface AnalysisContext {
  finding: FindingWithDisplayName;
  history: FindingHistoryRow[];
  prior_analyses: Omit<AnalysisRequestRow, 'context'>[];
  knownClient: { name: string; network: string } | null;
  firewallSummary: unknown | null;
  recentEvents: (StoredEvent & { homelab: ReturnType<typeof lookupHomelabService> })[];
  baselineHistory: BaselineRow[];
  since_last_decision: { since: string; total: number; unblocked_ips_alerts: number } | null;
  recheck: { before: ActivitySummary; after: ActivitySummary } | null;
}

function getBaselineHistory(lensDb: LensDb, category: string, signature: string): BaselineRow[] {
  return lensDb.conn
    .prepare(
      `SELECT day, count FROM baselines WHERE category = ? AND signature = ?
       ORDER BY day DESC LIMIT ?`
    )
    .all(category, signature, BASELINE_HISTORY_LIMIT) as unknown as BaselineRow[];
}

// A failed events query yields null for that part rather than failing the
// whole bundle.
function orNull<T>(label: string, fn: () => T): T | null {
  try {
    return fn();
  } catch (err) {
    console.error(`Analysis context: ${label} failed:`, err);
    return null;
  }
}

function recentEventsFor(eventsDb: EventsDb, finding: Finding): StoredEvent[] {
  if (finding.entity_type === 'source_ip') {
    return eventsForSourceIp(eventsDb, finding.entity_key, RECENT_EVENTS_LIMIT);
  }
  if (finding.entity_type === 'client') {
    return eventsForClientMac(eventsDb, finding.entity_key, RECENT_EVENTS_LIMIT);
  }
  const { category, signature } = splitSignatureKey(finding.entity_key);
  return eventsForSignature(eventsDb, category, signature, RECENT_EVENTS_LIMIT);
}

// True when the finding is triaging only because internal_source reopened it
// after a rule close: the last row that isn't a trigger_added/queued is the
// rule_closed, with a trigger_added after it. closeByRule stamped
// last_triaged_at with the run time, so a window starting there would hide the
// very events that created the finding.
function reopenedAfterRuleClose(finding: Finding, history: FindingHistoryRow[]): boolean {
  if (finding.status !== 'triaging') return false;
  let sawTrigger = false;
  for (let i = history.length - 1; i >= 0; i--) {
    const { kind } = history[i];
    if (kind === 'trigger_added') sawTrigger = true;
    else if (kind !== 'queued') return kind === 'rule_closed' && sawTrigger;
  }
  return false;
}

function sinceLastDecisionStart(finding: Finding, history: FindingHistoryRow[]): string {
  if (reopenedAfterRuleClose(finding, history)) {
    return new Date(
      Date.parse(finding.first_seen) - NEW_ENTITY_WINDOW_HOURS * 3600 * 1000
    ).toISOString();
  }
  return decisionWindowStart(finding);
}

export async function buildAnalysisContext(
  deps: AnalysisDeps,
  request: AnalysisRequestRow,
  finding: Finding,
  nowIso: string
): Promise<AnalysisContext> {
  const { lensDb, eventsDb, unifiMcp, homelabServices } = deps;
  const knownClient =
    finding.entity_type === 'source_ip' ? await unifiMcp.resolveClient(finding.entity_key) : null;
  const firewallSummary = await unifiMcp.getFirewallSummary();

  const priorAnalyses = getAnalysisRequestsForFinding(lensDb, finding.id as number)
    .filter((r) => r.status === 'answered' && r.id !== request.id)
    .map(({ context: _context, ...rest }) => rest);
  const history = listHistory(lensDb, finding.id as number);

  const { entity_type: type, entity_key: key } = finding;
  const recentEvents: StoredEvent[] =
    orNull('recent events', () => recentEventsFor(eventsDb, finding)) ?? [];
  let baselineHistory: BaselineRow[] = [];
  if (type === 'signature') {
    const { category, signature } = splitSignatureKey(key);
    baselineHistory = getBaselineHistory(lensDb, category, signature);
  }

  const since = sinceLastDecisionStart(finding, history);
  const sinceLastDecision: AnalysisContext['since_last_decision'] = orNull(
    'since-last-decision counts',
    () => ({
      since,
      total: entityActivitySummary(eventsDb, type, key, since).total,
      unblocked_ips_alerts: countUnblockedIpsAlerts(eventsDb, type, key, since),
    })
  );
  let recheck: AnalysisContext['recheck'] = null;
  if (request.is_recheck) {
    const beforeStart = new Date(Date.parse(since) - RECHECK_BEFORE_DAYS * DAY_MS).toISOString();
    recheck = orNull('recheck summaries', () => ({
      before: entityActivitySummary(eventsDb, type, key, beforeStart, since),
      after: entityActivitySummary(eventsDb, type, key, since, nowIso),
    }));
  }

  return {
    finding: withDisplayNames(eventsDb, [finding])[0],
    history,
    prior_analyses: priorAnalyses,
    knownClient,
    firewallSummary,
    recentEvents: annotateHomelabDestinations(recentEvents, homelabServices),
    baselineHistory,
    since_last_decision: sinceLastDecision,
    recheck,
  };
}
