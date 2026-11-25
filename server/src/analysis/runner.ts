import { addHistory } from '../db/findingHistoryStore.js';
import {
  bumpLastActivity,
  getFinding,
  hasSeenSignature,
  hasSeenSourceIp,
  listFindings,
  markSeenClient,
  markSeenSignature,
  markSeenSourceIp,
  seenClientMacs,
  upsertFinding,
} from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';
import type { SinkDb } from '../db/sinkDb.js';
import {
  allClientMacs,
  clientDayCounts,
  clientLastActivitySince,
  clientMacsSince,
} from '../db/sinkQueries.js';
import type { HomelabRegistry } from '../enrichment/homelabServices.js';
import { computeBaseline, isAnomalous } from './baseline.js';
import { isInternalSource } from './cidr.js';
import {
  applyTrigger,
  decisionWindowStart,
  type Finding,
  isRecheckDue,
  reevaluateTrigger,
  type TriggerType,
} from './findings.js';
import { matchRules, type RuleName } from './matchRules.js';
import {
  detectNewClients,
  detectNewSignatures,
  detectNewSourceIps,
  isIgnoredSignature,
  signatureKey,
} from './newEntity.js';
import {
  atomically,
  closeByRule,
  queueForAnalysis,
  recheckRequeue,
  recheckStillClosed,
  recordCreated,
} from './pipeline.js';
import { isSustained, REPEAT_OFFENDER_WINDOW_DAYS } from './repeatOffender.js';

export interface RunnerDeps {
  sinkDb: SinkDb;
  lensDb: LensDb;
  lanCidrs: string[];
  trustedAdminNames: string[];
  safeSignaturePrefixes: string[];
  // Optional: per-deployment registry of known homelab hosts/services (see
  // enrichment/homelabServices.ts). Absent/empty is a genuine no-op for
  // matchRules' homelab-service-egress and exposed-host checks, same tolerance
  // pattern as the rest of that module's optional local config.
  homelabServices?: HomelabRegistry;
}

const NEW_ENTITY_WINDOW_HOURS = 24;

interface RecentEventRow {
  received_at: string;
  category: string;
  signature: string | null;
  source_ip: string | null;
}

function recentEvents(sinkDb: SinkDb, sinceIso: string): RecentEventRow[] {
  const rows = sinkDb.conn
    .prepare(
      'SELECT received_at, category, signature, source_ip FROM events WHERE received_at >= ?'
    )
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

interface RecordedTrigger {
  finding: Finding;
  created: boolean;
  reopened: boolean;
}

// Applies a trigger and records what it did to the finding's history: `created`
// for a brand-new finding, `trigger_added` when an existing one gains a trigger
// type it didn't have. `reopened` is applyTrigger's one status change (a
// rule-closed finding gaining internal_source goes back to triaging).
function recordTrigger(
  deps: RunnerDeps,
  existing: Finding | null,
  type: TriggerType,
  nowIso: string,
  entityType: Finding['entity_type'],
  entityKey: string
): RecordedTrigger {
  return atomically(deps.lensDb, () => {
    const finding = upsertFinding(
      deps.lensDb,
      applyTrigger(existing, type, nowIso, entityType, entityKey)
    );
    const reopened = existing?.status === 'closed' && finding.status === 'triaging';
    if (!existing) {
      recordCreated(deps.lensDb, finding, nowIso);
    } else if (!existing.triggers.some((t) => t.type === type)) {
      addHistory(deps.lensDb, {
        finding_id: finding.id as number,
        at: nowIso,
        kind: 'trigger_added',
        actor: 'system',
        summary: reopened
          ? `Trigger added: ${type}; reopened for triage`
          : `Trigger added: ${type}`,
      });
    }
    return { finding, created: !existing, reopened };
  });
}

// Every new (or reopened) finding goes through the rules first; whatever no
// rule fully explains is queued for AI analysis. Only call this for a finding
// that was just created or reopened: those never have a pending request, and
// queueForAnalysis would otherwise record a second `queued` row.
function routeToPipeline(
  deps: RunnerDeps,
  finding: Finding,
  sinceIso: string,
  untilIso: string | undefined,
  nowIso: string,
  allowedRules?: RuleName[]
): void {
  // Fail towards the AI: the finding is already committed as triaging and its
  // entity marked seen, so if a sink query throws here and we let it escape,
  // nothing would ever route it again (stuck triaging with no request).
  let match: ReturnType<typeof matchRules> = null;
  try {
    match = matchRules(deps, finding, sinceIso, untilIso, allowedRules);
  } catch (err) {
    console.error(
      `Rule matching failed for ${finding.entity_type} ${finding.entity_key}; queueing for AI:`,
      err
    );
  }
  if (match) closeByRule(deps.lensDb, finding, match, nowIso);
  else queueForAnalysis(deps.lensDb, finding, nowIso);
}

function routeIfNew(
  deps: RunnerDeps,
  r: RecordedTrigger,
  sinceIso: string,
  untilIso: string | undefined,
  nowIso: string,
  allowedRules?: RuleName[]
): void {
  if (r.created || r.reopened) {
    routeToPipeline(deps, r.finding, sinceIso, untilIso, nowIso, allowedRules);
  }
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
      const key = signatureKey(category, signature);
      const r = recordTrigger(
        deps,
        getFinding(deps.lensDb, 'signature', key),
        'new_signature',
        nowIso,
        'signature',
        key
      );
      markSeenSignature(deps.lensDb, category, signature, nowIso);
      routeIfNew(deps, r, sinceIso, undefined, nowIso);
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
      const r = recordTrigger(
        deps,
        getFinding(deps.lensDb, 'source_ip', ip),
        'new_source_ip',
        nowIso,
        'source_ip',
        ip
      );
      markSeenSourceIp(deps.lensDb, ip, nowIso);
      routeIfNew(deps, r, sinceIso, undefined, nowIso);
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
      const r = recordTrigger(
        deps,
        getFinding(deps.lensDb, 'source_ip', ip),
        'internal_source',
        nowIso,
        'source_ip',
        ip
      );
      count++;

      // A finding created here, or a rule-closed one this trigger just
      // reopened, still goes through the rules — but only operational_noise
      // may close it (matchRules enforces that for any internal_source
      // finding). Being on the LAN carries no security signal for purely
      // operational telemetry; anything else from an internal host is the
      // "possible compromised host talking out" case and must reach AI.
      routeIfNew(deps, r, sinceIso, undefined, nowIso, ['operational_noise']);
    }
    return count;
  });

  // Client: LAN hosts UniFi identified only by MAC (source_ip NULL) on
  // Security events — invisible to the IP-keyed checks above. New clients are
  // every client MAC in all of sink history minus seen_clients, so the first
  // run after deploy seeds findings for historical client-only alerts and
  // later runs behave like the new-source-ip check. Every client gets
  // internal_source (UniFi-named clients are LAN by definition) so client
  // findings rank alongside internal IP findings. No rule matches a client
  // (matchRules returns null), so routing always queues for AI. Only the
  // client-only queries touch the sink v1.0.3 columns, so on an older sink
  // this check fails alone.
  touched += runCheck('client', () => {
    let count = 0;
    const newMacs = detectNewClients(allClientMacs(deps.sinkDb), seenClientMacs(deps.lensDb));
    for (const mac of newMacs) {
      const withNew = recordTrigger(
        deps,
        getFinding(deps.lensDb, 'client', mac),
        'new_client',
        nowIso,
        'client',
        mac
      );
      const withInternal = recordTrigger(
        deps,
        withNew.finding,
        'internal_source',
        nowIso,
        'client',
        mac
      );
      // Route once, after both triggers are on the finding. (A client is never
      // rule-closed, so new_client can't reopen one; only creation or the
      // internal_source reopen can.)
      if (withNew.created || withInternal.reopened) {
        routeToPipeline(deps, withInternal.finding, sinceIso, undefined, nowIso);
      }
      markSeenClient(deps.lensDb, mac, nowIso);
      count++;
    }
    const newMacSet = new Set(newMacs);
    for (const mac of clientMacsSince(deps.sinkDb, sinceIso)) {
      if (newMacSet.has(mac)) continue;
      const r = recordTrigger(
        deps,
        getFinding(deps.lensDb, 'client', mac),
        'internal_source',
        nowIso,
        'client',
        mac
      );
      routeIfNew(deps, r, sinceIso, undefined, nowIso);
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
        const r = recordTrigger(
          deps,
          existing,
          'repeat_offender',
          nowIso,
          'source_ip',
          row.source_ip
        );
        routeIfNew(deps, r, windowStart, undefined, nowIso);
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
        const r = recordTrigger(deps, existing, 'repeat_offender', nowIso, 'client', row.mac);
        routeIfNew(deps, r, windowStart, undefined, nowIso);
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

  // Last activity: the recheck predicate compares last_activity_at against the
  // last decision, so keep it at the newest event seen for each entity. Bumps
  // only ever move it forward and don't count as touching a finding.
  runCheck('last-activity', () => {
    const bySourceIp = new Map<string, string>();
    const bySignature = new Map<string, string>();
    const keepMax = (m: Map<string, string>, key: string, at: string) => {
      const prev = m.get(key);
      if (prev === undefined || at > prev) m.set(key, at);
    };
    for (const e of events) {
      if (e.source_ip) keepMax(bySourceIp, e.source_ip, e.received_at);
      if (e.signature) keepMax(bySignature, signatureKey(e.category, e.signature), e.received_at);
    }
    for (const [ip, at] of bySourceIp) bumpLastActivity(deps.lensDb, 'source_ip', ip, at);
    for (const [key, at] of bySignature) bumpLastActivity(deps.lensDb, 'signature', key, at);
    return 0;
  });

  // Separate from 'last-activity' so an old sink (no client columns) loses
  // only client activity.
  runCheck('last-activity-client', () => {
    for (const { mac, last_received_at } of clientLastActivitySince(deps.sinkDb, sinceIso)) {
      bumpLastActivity(deps.lensDb, 'client', mac, last_received_at);
    }
    return 0;
  });

  return { findingsTouched: touched };
}

const BASELINE_HISTORY_LOOKBACK_DAYS = 30;

export function runDailyAnomalyCheck(
  deps: RunnerDeps,
  day: string = new Date(Date.now() - 86400000).toISOString().slice(0, 10),
  now: Date = new Date()
): { findingsTouched: number } {
  const nowIso = now.toISOString();
  const dayStart = `${day}T00:00:00.000Z`;
  const dayEnd = new Date(Date.parse(dayStart) + 24 * 3600 * 1000).toISOString();

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
      const r = recordTrigger(
        deps,
        getFinding(deps.lensDb, 'signature', key),
        'anomaly',
        nowIso,
        'signature',
        key
      );
      routeIfNew(deps, r, dayStart, dayEnd, nowIso);
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

export interface RecheckResult {
  checked: number;
  stillClosed: number;
  requeued: number;
}

// Daily recheck of closed findings that saw new activity since their last
// decision (isRecheckDue also rate-limits each finding to once per 24h). A
// rule that still explains everything since that decision keeps it closed;
// anything else goes back to the AI queue as a recheck. Client findings never
// match a rule, so new client activity always requeues.
export function runDailyRecheck(deps: RunnerDeps, now: Date = new Date()): RecheckResult {
  const nowIso = now.toISOString();
  const result: RecheckResult = { checked: 0, stillClosed: 0, requeued: 0 };
  const due = listFindings(deps.lensDb, { view: 'closed' }).filter((f) => isRecheckDue(f, nowIso));
  for (const finding of due) {
    result.checked++;
    // runCheck for per-finding isolation; its return value is unused here.
    runCheck(`recheck ${finding.entity_type} ${finding.entity_key}`, () => {
      const match = matchRules(deps, finding, decisionWindowStart(finding));
      if (match) {
        recheckStillClosed(deps.lensDb, finding, match, nowIso);
        result.stillClosed++;
      } else {
        recheckRequeue(deps.lensDb, finding, nowIso);
        result.requeued++;
      }
      return 1;
    });
  }
  return result;
}

export interface BackfillResult {
  checked: number;
  closed: number;
  byRule: Record<RuleName, number>;
}

// The window the creation pass used for this finding, reproduced relative to
// `first_seen`. `first_seen` is stamped with the detection *run* time, at the
// *end* of the window that run scanned, so every window here ends at or before
// it — never `[first_seen, first_seen + 24h)`. The creating trigger
// (`triggers[0]`) picks the width:
// - repeat_offender: `[first_seen - 14d, first_seen)`, the repeat-offender scan.
// - anomaly: the anomaly day `[D, D+1)`, with D = date(first_seen - 24h) — the
//   daily job judges the day before it runs, so this holds even if it ran late.
//   It assumes the scheduled run: a manual runDailyAnomalyCheck for an older
//   explicit `day` still stamps first_seen = now, so D would be the wrong day.
// - anything else: `[first_seen - 24h, first_seen)`, the hourly scan.
export function backfillWindow(finding: Finding): { sinceIso: string; untilIso: string } {
  const firstSeenMs = Date.parse(finding.first_seen);
  const hoursBefore = (h: number) => new Date(firstSeenMs - h * 3600 * 1000).toISOString();
  switch (finding.triggers[0]?.type) {
    case 'repeat_offender':
      return {
        sinceIso: hoursBefore(REPEAT_OFFENDER_WINDOW_DAYS * 24),
        untilIso: new Date(firstSeenMs).toISOString(),
      };
    case 'anomaly': {
      const dayStart = `${hoursBefore(24).slice(0, 10)}T00:00:00.000Z`;
      return {
        sinceIso: dayStart,
        untilIso: new Date(Date.parse(dayStart) + 24 * 3600 * 1000).toISOString(),
      };
    }
    default:
      return {
        sinceIso: hoursBefore(NEW_ENTITY_WINDOW_HOURS),
        untilIso: new Date(firstSeenMs).toISOString(),
      };
  }
}

// Catch-up rule pass over never-decided findings still waiting on AI, e.g. ones
// created before a rule existed or before TRUSTED_ADMIN_NAMES was configured.
// The live path only evaluates a finding at the moment it's created, so this
// re-runs the rules over the same window that creation used (backfillWindow):
// a narrower window could let recent matching events stand in for "every event
// backing the finding" and close one creation deliberately queued. A match
// closes the finding by rule, which cancels its pending AI request.
export function runRuleTriageBackfill(deps: RunnerDeps, now: Date = new Date()): BackfillResult {
  const nowIso = now.toISOString();
  const result: BackfillResult = {
    checked: 0,
    closed: 0,
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

  // Client findings get no rule triage (see matchRules' guard), so they
  // aren't candidates at all — keeps `checked` honest. Only never-decided
  // findings (last_triaged_at null) are candidates: a triaging finding that
  // was decided before — requeued by the daily recheck, reopened by an
  // internal_source trigger, or sent back by an operator's re-analyze — is
  // there because of what happened after that decision, so its creation
  // window is stale and a rule match on it must not close the finding.
  const candidates = listFindings(deps.lensDb, { view: 'triaging' }).filter(
    (f) => f.entity_type !== 'client' && f.last_triaged_at === null
  );

  for (const finding of candidates) {
    result.checked++;
    const { sinceIso, untilIso } = backfillWindow(finding);
    const match = matchRules(deps, finding, sinceIso, untilIso);
    if (match) {
      closeByRule(deps.lensDb, finding, match, nowIso);
      result.closed++;
      result.byRule[match.rule]++;
    }
  }

  return result;
}
