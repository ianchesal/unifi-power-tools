import { createAnsweredRuleAnalysis } from '../db/analysisRequestsStore.js';
import {
  getFinding,
  hasSeenSignature,
  hasSeenSourceIp,
  listFindings,
  markSeenClient,
  markSeenSignature,
  markSeenSourceIp,
  seenClientMacs,
  updateFindingState,
  upsertFinding,
} from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';
import type { SinkDb } from '../db/sinkDb.js';
import { allClientMacs, clientDayCounts, clientMacsSince } from '../db/sinkQueries.js';
import type { HomelabRegistry } from '../enrichment/homelabServices.js';
import { computeBaseline, isAnomalous } from './baseline.js';
import { isInternalSource } from './cidr.js';
import { applyTrigger, type Finding, reevaluateTrigger } from './findings.js';
import { matchRules, type RuleName } from './matchRules.js';
import {
  detectNewClients,
  detectNewSignatures,
  detectNewSourceIps,
  isIgnoredSignature,
  signatureKey,
} from './newEntity.js';
import { isSustained, REPEAT_OFFENDER_WINDOW_DAYS } from './repeatOffender.js';

export interface RunnerDeps {
  sinkDb: SinkDb;
  lensDb: LensDb;
  lanCidrs: string[];
  trustedAdminNames: string[];
  safeSignaturePrefixes: string[];
  // Optional: per-deployment registry of known homelab hosts/services (see
  // enrichment/homelabServices.ts). Absent/empty is a genuine no-op for
  // tryRuleTriage's homelab-service-egress check, same tolerance pattern as
  // the rest of that module's optional local config.
  homelabServices?: HomelabRegistry;
}

const NEW_ENTITY_WINDOW_HOURS = 24;

interface RecentEventRow {
  category: string;
  signature: string | null;
  source_ip: string | null;
}

function recentEvents(sinkDb: SinkDb, sinceIso: string): RecentEventRow[] {
  const rows = sinkDb.conn
    .prepare('SELECT category, signature, source_ip FROM events WHERE received_at >= ?')
    .all(sinceIso) as unknown as RecentEventRow[];
  return rows.filter((e) => !(e.signature && isIgnoredSignature(e.category, e.signature)));
}

// Runs a single named check in isolation: a failure here is logged and contributes
// zero to the total, but must not prevent the other checks in the run from executing
// (Global Constraint: "All heuristics run in isolation from each other — one broken
// heuristic must not block the others").
function runCheck(name: string, fn: () => number): number {
  try {
    return fn();
  } catch (err) {
    console.error(`Analysis check "${name}" failed:`, err);
    return 0;
  }
}

export type { RuleName } from './matchRules.js';

// Rule match + the (temporary, until Task 5/6 rewire) legacy writes: records an
// already-answered rule analysis and closes the finding.
function tryRuleTriage(
  deps: RunnerDeps,
  finding: Finding,
  sinceIso: string,
  nowIso: string,
  untilIso?: string,
  allowedRules?: RuleName[]
): { matched: boolean; rule?: RuleName } {
  const match = matchRules(deps, finding, sinceIso, untilIso, allowedRules);
  if (!match) return { matched: false };
  createAnsweredRuleAnalysis(
    deps.lensDb,
    finding.id as number,
    { finding },
    match.verdict.recommendation,
    match.verdict.riskLevel,
    nowIso
  );
  updateFindingState(deps.lensDb, finding.id as number, {
    status: 'closed',
    closed_by: 'rule',
    closed_reason: match.verdict.recommendation,
    closed_at: nowIso,
    last_triaged_at: nowIso,
  });
  return { matched: true, rule: match.rule };
}

export function runHourlyChecks(
  deps: RunnerDeps,
  now: Date = new Date()
): { findingsTouched: number } {
  const nowIso = now.toISOString();
  const sinceIso = new Date(now.getTime() - NEW_ENTITY_WINDOW_HOURS * 3600 * 1000).toISOString();
  const events = recentEvents(deps.sinkDb, sinceIso);
  let touched = 0;

  // New-signature / new-source-ip
  touched += runCheck('new-signature', () => {
    let count = 0;
    const seenSigSet = new Set(
      events
        .filter((e) => e.signature && hasSeenSignature(deps.lensDb, e.category, e.signature))
        .map((e) => signatureKey(e.category, e.signature as string))
    );
    for (const { category, signature } of detectNewSignatures(events, seenSigSet)) {
      const existing = getFinding(deps.lensDb, 'signature', signatureKey(category, signature));
      const finding = upsertFinding(
        deps.lensDb,
        applyTrigger(
          existing,
          'new_signature',
          nowIso,
          'signature',
          signatureKey(category, signature)
        )
      );
      markSeenSignature(deps.lensDb, category, signature, nowIso);
      tryRuleTriage(deps, finding, sinceIso, nowIso);
      count++;
    }
    return count;
  });

  touched += runCheck('new-source-ip', () => {
    let count = 0;
    const seenIpSet = new Set(
      events
        .filter((e) => e.source_ip && hasSeenSourceIp(deps.lensDb, e.source_ip))
        .map((e) => e.source_ip as string)
    );
    for (const ip of detectNewSourceIps(events, seenIpSet)) {
      const existing = getFinding(deps.lensDb, 'source_ip', ip);
      const finding = upsertFinding(
        deps.lensDb,
        applyTrigger(existing, 'new_source_ip', nowIso, 'source_ip', ip)
      );
      markSeenSourceIp(deps.lensDb, ip, nowIso);
      tryRuleTriage(deps, finding, sinceIso, nowIso);
      count++;
    }
    return count;
  });

  // Internal-source
  touched += runCheck('internal-source', () => {
    let count = 0;
    const distinctIps = new Set(
      events.filter((e) => e.source_ip).map((e) => e.source_ip as string)
    );
    for (const ip of distinctIps) {
      if (!isInternalSource(ip, deps.lanCidrs)) continue;
      const existing = getFinding(deps.lensDb, 'source_ip', ip);
      const finding = upsertFinding(
        deps.lensDb,
        applyTrigger(existing, 'internal_source', nowIso, 'source_ip', ip)
      );
      count++;

      // Being on the LAN carries no security signal for a finding whose
      // events are all non-security operational telemetry — every client is
      // internal by definition, so the flag adds nothing there. Give it the
      // same operational-noise auto-dismiss the new-source-ip loop already
      // would, restricted to that one rule (see tryRuleTriage's allowedRules
      // doc) — otherwise a purely-operational internal finding sits stuck at
      // `new` until someone runs the admin backfill by hand.
      if (finding.status !== 'closed') {
        tryRuleTriage(deps, finding, sinceIso, nowIso, undefined, ['operational_noise']);
      }
    }
    return count;
  });

  // Client: LAN hosts UniFi identified only by MAC (source_ip NULL) on
  // Security events — invisible to the IP-keyed checks above. New clients are
  // every client MAC in all of sink history minus seen_clients, so the first
  // run after deploy seeds findings for historical client-only alerts and
  // later runs behave like the new-source-ip check. Every client gets
  // internal_source (UniFi-named clients are LAN by definition) so client
  // findings rank alongside internal IP findings. No rule triage. Only the
  // client-only queries touch the sink v1.0.3 columns, so on an older sink
  // this check fails alone.
  touched += runCheck('client', () => {
    let count = 0;
    const newMacs = detectNewClients(allClientMacs(deps.sinkDb), seenClientMacs(deps.lensDb));
    for (const mac of newMacs) {
      const withNew = upsertFinding(
        deps.lensDb,
        applyTrigger(getFinding(deps.lensDb, 'client', mac), 'new_client', nowIso, 'client', mac)
      );
      upsertFinding(deps.lensDb, applyTrigger(withNew, 'internal_source', nowIso, 'client', mac));
      markSeenClient(deps.lensDb, mac, nowIso);
      count++;
    }
    const newMacSet = new Set(newMacs);
    for (const mac of clientMacsSince(deps.sinkDb, sinceIso)) {
      if (newMacSet.has(mac)) continue;
      upsertFinding(
        deps.lensDb,
        applyTrigger(
          getFinding(deps.lensDb, 'client', mac),
          'internal_source',
          nowIso,
          'client',
          mac
        )
      );
      count++;
    }
    return count;
  });

  // Repeat-offender: recompute distinct-day activity over the trailing window directly
  // from events.db each run (homelab data volumes make this cheap; avoids incremental-
  // cursor bookkeeping — see spec's "runner queries the window directly" note).
  touched += runCheck('repeat-offender', () => {
    let count = 0;
    const windowStart = new Date(
      now.getTime() - REPEAT_OFFENDER_WINDOW_DAYS * 24 * 3600 * 1000
    ).toISOString();
    const ipDayCounts = deps.sinkDb.conn
      .prepare(
        `SELECT source_ip, COUNT(DISTINCT date(received_at)) as days FROM events
         WHERE received_at >= ? AND source_ip IS NOT NULL GROUP BY source_ip`
      )
      .all(windowStart) as { source_ip: string; days: number }[];

    const activeSustainedIps = new Set(
      ipDayCounts.filter((r) => isSustained(r.days)).map((r) => r.source_ip)
    );

    for (const row of ipDayCounts) {
      const existing = getFinding(deps.lensDb, 'source_ip', row.source_ip);
      if (isSustained(row.days)) {
        upsertFinding(
          deps.lensDb,
          applyTrigger(existing, 'repeat_offender', nowIso, 'source_ip', row.source_ip)
        );
        count++;
      } else if (existing?.triggers.some((t) => t.type === 'repeat_offender' && t.active)) {
        upsertFinding(deps.lensDb, reevaluateTrigger(existing, 'repeat_offender', false, nowIso));
        count++;
      }
    }
    // Any previously-sustained IP that dropped out of the window entirely (no rows at all)
    for (const finding of listFindings(deps.lensDb, { view: 'all' })) {
      if (finding.entity_type !== 'source_ip') continue;
      if (activeSustainedIps.has(finding.entity_key)) continue;
      if (!finding.triggers.some((t) => t.type === 'repeat_offender' && t.active)) continue;
      upsertFinding(deps.lensDb, reevaluateTrigger(finding, 'repeat_offender', false, nowIso));
      count++;
    }
    return count;
  });

  // Client repeat-offender: same rule as the IP pass, over client-only rows
  // keyed by MAC. Its own runCheck so an old sink (no client columns) can't
  // take the IP pass down with it.
  touched += runCheck('repeat-offender-client', () => {
    let count = 0;
    const windowStart = new Date(
      now.getTime() - REPEAT_OFFENDER_WINDOW_DAYS * 24 * 3600 * 1000
    ).toISOString();
    const macDayCounts = clientDayCounts(deps.sinkDb, windowStart);
    const activeSustainedMacs = new Set(
      macDayCounts.filter((r) => isSustained(r.days)).map((r) => r.mac)
    );

    for (const row of macDayCounts) {
      const existing = getFinding(deps.lensDb, 'client', row.mac);
      if (isSustained(row.days)) {
        upsertFinding(
          deps.lensDb,
          applyTrigger(existing, 'repeat_offender', nowIso, 'client', row.mac)
        );
        count++;
      } else if (existing?.triggers.some((t) => t.type === 'repeat_offender' && t.active)) {
        upsertFinding(deps.lensDb, reevaluateTrigger(existing, 'repeat_offender', false, nowIso));
        count++;
      }
    }
    for (const finding of listFindings(deps.lensDb, { view: 'all' })) {
      if (finding.entity_type !== 'client') continue;
      if (activeSustainedMacs.has(finding.entity_key)) continue;
      if (!finding.triggers.some((t) => t.type === 'repeat_offender' && t.active)) continue;
      upsertFinding(deps.lensDb, reevaluateTrigger(finding, 'repeat_offender', false, nowIso));
      count++;
    }
    return count;
  });

  return { findingsTouched: touched };
}

const BASELINE_HISTORY_LOOKBACK_DAYS = 30;

export function runDailyAnomalyCheck(
  deps: RunnerDeps,
  day: string = new Date(Date.now() - 86400000).toISOString().slice(0, 10)
): { findingsTouched: number } {
  const nowIso = new Date().toISOString();

  const touched = runCheck('daily-anomaly', () => {
    let count = 0;

    // Backfill baselines for prior days directly from the sink DB. In steady-state
    // production this is a no-op (each prior day's row was already written by that
    // day's own run), but it means a fresh lens.db — or a gap from missed runs —
    // still has real history to judge today's count against, instead of silently
    // skipping the anomaly check for lack of `baselines` rows.
    const lookbackStart = new Date(
      new Date(`${day}T00:00:00Z`).getTime() - BASELINE_HISTORY_LOOKBACK_DAYS * 24 * 3600 * 1000
    )
      .toISOString()
      .slice(0, 10);
    const historicalCounts = deps.sinkDb.conn
      .prepare(
        `SELECT date(received_at) as day, category, signature, COUNT(*) as count FROM events
       WHERE date(received_at) >= ? AND date(received_at) < ? AND signature IS NOT NULL AND signature != ''
       GROUP BY day, category, signature`
      )
      .all(lookbackStart, day) as {
      day: string;
      category: string;
      signature: string;
      count: number;
    }[];
    for (const row of historicalCounts) {
      if (isIgnoredSignature(row.category, row.signature)) continue;
      deps.lensDb.conn
        .prepare(
          `INSERT OR IGNORE INTO baselines (category, signature, day, count) VALUES (?, ?, ?, ?)`
        )
        .run(row.category, row.signature, row.day, row.count);
    }

    const allDayCounts = deps.sinkDb.conn
      .prepare(
        `SELECT category, signature, COUNT(*) as count FROM events
       WHERE date(received_at) = ? AND signature IS NOT NULL AND signature != ''
       GROUP BY category, signature`
      )
      .all(day) as { category: string; signature: string; count: number }[];
    const dayCounts = allDayCounts.filter((r) => !isIgnoredSignature(r.category, r.signature));

    for (const row of dayCounts) {
      deps.lensDb.conn
        .prepare(
          `INSERT OR IGNORE INTO baselines (category, signature, day, count) VALUES (?, ?, ?, ?)`
        )
        .run(row.category, row.signature, day, row.count);
    }

    const activeAnomalies = new Set<string>();
    for (const row of dayCounts) {
      const history = deps.lensDb.conn
        .prepare(
          `SELECT count FROM baselines WHERE category = ? AND signature = ? AND day < ?
         ORDER BY day DESC LIMIT 14`
        )
        .all(row.category, row.signature, day) as { count: number }[];
      if (history.length < 3) continue; // not enough history to judge yet
      const stats = computeBaseline(history.map((h) => h.count));
      if (!isAnomalous(row.count, stats)) continue;

      const key = signatureKey(row.category, row.signature);
      activeAnomalies.add(key);
      const existing = getFinding(deps.lensDb, 'signature', key);
      upsertFinding(deps.lensDb, applyTrigger(existing, 'anomaly', nowIso, 'signature', key));
      count++;
    }

    for (const finding of listFindings(deps.lensDb, { view: 'all' })) {
      if (finding.entity_type !== 'signature') continue;
      if (activeAnomalies.has(finding.entity_key)) continue;
      if (!finding.triggers.some((t) => t.type === 'anomaly' && t.active)) continue;
      upsertFinding(deps.lensDb, reevaluateTrigger(finding, 'anomaly', false, nowIso));
      count++;
    }

    return count;
  });

  return { findingsTouched: touched };
}

export interface BackfillResult {
  checked: number;
  dismissed: number;
  byRule: Record<RuleName, number>;
}

// One-off catch-up for findings created before rule-based triage existed (or
// before it was configured) — the live path only ever evaluates a finding at
// the moment it's created, so anything already sitting in the findings table
// as 'new'/'acknowledged' never gets a rule pass otherwise. Re-checks every
// such finding against the same three rules, reproducing the live path's own
// window relative to `first_seen`: `first_seen` is stamped with the
// detection *run* time (`nowIso` in runHourlyChecks), sitting at the *end*
// of the trailing 24h window the live path scanned, not the start — the
// underlying events that triggered detection are all *before* first_seen,
// not after it. So the backfill window is `[first_seen - 24h, first_seen)`,
// not `[first_seen, first_seen + 24h)`. Runs against every candidate finding
// regardless of whether it already has an AI-answered analysis request — a
// rule match adds a second, rule-sourced request and dismisses the finding
// either way.
export function runRuleTriageBackfill(deps: RunnerDeps): BackfillResult {
  const nowIso = new Date().toISOString();
  const result: BackfillResult = {
    checked: 0,
    dismissed: 0,
    byRule: {
      admin_login: 0,
      operational_noise: 0,
      low_signal_category: 0,
      reputation_blocklist: 0,
      homelab_service_egress: 0,
      exposed_host_scan: 0,
      ignored_signature: 0,
    },
  };

  // Client findings get no rule triage (see tryRuleTriage's guard), so they
  // aren't candidates at all — keeps `checked` honest.
  const candidates = listFindings(deps.lensDb, { view: 'all' }).filter(
    (f) => f.entity_type !== 'client' && f.status !== 'closed'
  );

  for (const finding of candidates) {
    result.checked++;
    const untilIso = finding.first_seen;
    const sinceIso = new Date(
      new Date(finding.first_seen).getTime() - NEW_ENTITY_WINDOW_HOURS * 3600 * 1000
    ).toISOString();
    const outcome = tryRuleTriage(deps, finding, sinceIso, nowIso, untilIso);
    if (outcome.matched && outcome.rule) {
      result.dismissed++;
      result.byRule[outcome.rule]++;
    }
  }

  return result;
}
