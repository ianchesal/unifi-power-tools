import { decisionWindowStart, type Finding } from '../analysis/findings.js';
import { splitSignatureKey } from '../analysis/newEntity.js';
import { type FindingWithDisplayName, withDisplayNames } from '../api/findings.js';
import {
  type AnalysisRequestRow,
  getAnalysisRequestsForFinding,
} from '../db/analysisRequestsStore.js';
import { type FindingHistoryRow, listHistory } from '../db/findingHistoryStore.js';
import type { LensDb } from '../db/lensDb.js';
import type { SinkDb } from '../db/sinkDb.js';
import {
  type ActivitySummary,
  countUnblockedIpsAlerts,
  entityActivitySummary,
  eventsForClientMac,
  eventsForSignature,
  eventsForSourceIp,
  type StoredEvent,
} from '../db/sinkQueries.js';
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
  sinkDb: SinkDb | null;
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

// A throw here is almost always a pre-v1.0.3 sink missing the client columns;
// treat it the same as having no sink rather than failing the whole bundle.
function orNull<T>(label: string, fn: () => T): T | null {
  try {
    return fn();
  } catch (err) {
    console.error(`Analysis context: ${label} failed:`, err);
    return null;
  }
}

function recentEventsFor(sinkDb: SinkDb, finding: Finding): StoredEvent[] {
  if (finding.entity_type === 'source_ip') {
    return eventsForSourceIp(sinkDb, finding.entity_key, RECENT_EVENTS_LIMIT);
  }
  if (finding.entity_type === 'client') {
    return eventsForClientMac(sinkDb, finding.entity_key, RECENT_EVENTS_LIMIT);
  }
  const { category, signature } = splitSignatureKey(finding.entity_key);
  return eventsForSignature(sinkDb, category, signature, RECENT_EVENTS_LIMIT);
}

export async function buildAnalysisContext(
  deps: AnalysisDeps,
  request: AnalysisRequestRow,
  finding: Finding,
  nowIso: string
): Promise<AnalysisContext> {
  const { lensDb, sinkDb, unifiMcp, homelabServices } = deps;
  const knownClient =
    finding.entity_type === 'source_ip' ? await unifiMcp.resolveClient(finding.entity_key) : null;
  const firewallSummary = await unifiMcp.getFirewallSummary();

  const priorAnalyses = getAnalysisRequestsForFinding(lensDb, finding.id as number)
    .filter((r) => r.status === 'answered' && r.id !== request.id)
    .map(({ context: _context, ...rest }) => rest);

  let recentEvents: StoredEvent[] = [];
  let baselineHistory: BaselineRow[] = [];
  let sinceLastDecision: AnalysisContext['since_last_decision'] = null;
  let recheck: AnalysisContext['recheck'] = null;
  if (sinkDb) {
    const { entity_type: type, entity_key: key } = finding;
    recentEvents = orNull('recent events', () => recentEventsFor(sinkDb, finding)) ?? [];
    if (type === 'signature') {
      const { category, signature } = splitSignatureKey(key);
      baselineHistory = getBaselineHistory(lensDb, category, signature);
    }

    const since = decisionWindowStart(finding);
    sinceLastDecision = orNull('since-last-decision counts', () => ({
      since,
      total: entityActivitySummary(sinkDb, type, key, since).total,
      unblocked_ips_alerts: countUnblockedIpsAlerts(sinkDb, type, key, since),
    }));
    if (request.is_recheck) {
      const beforeStart = new Date(Date.parse(since) - RECHECK_BEFORE_DAYS * DAY_MS).toISOString();
      recheck = orNull('recheck summaries', () => ({
        before: entityActivitySummary(sinkDb, type, key, beforeStart, since),
        after: entityActivitySummary(sinkDb, type, key, since, nowIso),
      }));
    }
  }

  return {
    finding: withDisplayNames(sinkDb, [finding])[0],
    history: listHistory(lensDb, finding.id as number),
    prior_analyses: priorAnalyses,
    knownClient,
    firewallSummary,
    recentEvents: annotateHomelabDestinations(recentEvents, homelabServices),
    baselineHistory,
    since_last_decision: sinceLastDecision,
    recheck,
  };
}
