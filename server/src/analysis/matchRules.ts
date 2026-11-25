import {
  auditCandidateEvents,
  signatureEventCounts,
  sourceIpEventCounts,
} from '../db/sinkQueries.js';
import type { Finding } from './findings.js';
import { isIgnoredSignature, splitSignatureKey } from './newEntity.js';
import {
  LOW_SIGNAL_SYSTEM_CATEGORIES,
  NON_SECURITY_OPERATIONAL_CATEGORIES,
  type TriageVerdict,
  tryAdminAuditLoginRule,
  tryExposedHostScanRule,
  tryHomelabServiceRule,
  tryIgnoredSignatureRule,
  tryLowSignalCategoryRule,
  tryOperationalNoiseRule,
  tryReputationBlocklistRule,
} from './ruleTriage.js';
import type { RunnerDeps } from './runner.js';

export type RuleName =
  | 'admin_login'
  | 'operational_noise'
  | 'low_signal_category'
  | 'reputation_blocklist'
  | 'homelab_service_egress'
  | 'exposed_host_scan'
  | 'ignored_signature';

export interface RuleMatch {
  rule: RuleName;
  verdict: TriageVerdict;
}

// Query-only rule evaluation for a finding: checks every backing event within
// [sinceIso, untilIso) (an open upper bound when untilIso is omitted, which is
// how the live hourly path calls this: the finding was *just* created/updated,
// so "now" is the natural upper bound). Returns the first rule (admin login,
// operational noise, reputation blocklist, exposed-host scan, ... — first match
// wins) that fully explains every event, or null. Never writes: callers decide
// what a match means (see pipeline.ts).
export function matchRules(
  deps: RunnerDeps,
  finding: Finding,
  sinceIso: string,
  untilIso?: string,
  // Restricts which rules may fire, in the same first-match-wins order.
  // Undefined tries every rule, unrestricted.
  allowedRules?: RuleName[]
): RuleMatch | null {
  // Client findings are backed only by client-only Security events (see
  // CLIENT_SECURITY_CATEGORIES) and get no rule triage — they always stay for
  // manual review. Guard explicitly so a client finding never falls into the
  // signature branch below and has its MAC parsed as a signature key.
  if (finding.entity_type === 'client') return null;

  // A finding carrying internal_source may only be closed by operational_noise.
  // An internal host tripping admin_login or reputation_blocklist is exactly the
  // "possible compromised host talking out" case internal-source flagging exists
  // to catch, and must keep surfacing for review. Being on the LAN carries no
  // security signal for purely operational telemetry, so that one rule stays.
  const internal = finding.triggers.some((t) => t.type === 'internal_source');
  const effective: RuleName[] | undefined = internal
    ? (allowedRules ?? ['operational_noise']).filter((r) => r === 'operational_noise')
    : allowedRules;
  const allowed = (r: RuleName) => !effective || effective.includes(r);
  const prefixClause = deps.safeSignaturePrefixes.map(() => 'signature LIKE ?').join(' OR ');
  const prefixParams = deps.safeSignaturePrefixes.map((p) => `${p}%`);

  let verdict: ReturnType<typeof tryAdminAuditLoginRule> = null;
  let rule: RuleName | undefined;

  if (finding.entity_type === 'source_ip') {
    if (allowed('admin_login') && deps.trustedAdminNames.length > 0) {
      const auditEvents = auditCandidateEvents(deps.sinkDb, finding.entity_key, sinceIso, untilIso);
      verdict = tryAdminAuditLoginRule(auditEvents, deps.trustedAdminNames);
      if (verdict) rule = 'admin_login';
    }

    if (!verdict && allowed('operational_noise')) {
      const opCounts = sourceIpEventCounts(
        deps.sinkDb,
        finding.entity_key,
        sinceIso,
        `category IN (${NON_SECURITY_OPERATIONAL_CATEGORIES.map(() => '?').join(',')})`,
        NON_SECURITY_OPERATIONAL_CATEGORIES,
        untilIso
      );
      verdict = tryOperationalNoiseRule(opCounts);
      if (verdict) rule = 'operational_noise';
    }

    if (!verdict && allowed('reputation_blocklist') && prefixClause) {
      const blockCounts = sourceIpEventCounts(
        deps.sinkDb,
        finding.entity_key,
        sinceIso,
        `category = 'ips_alert' AND action = 'blocked' AND (${prefixClause})`,
        prefixParams,
        untilIso
      );
      verdict = tryReputationBlocklistRule(blockCounts);
      if (verdict) rule = 'reputation_blocklist';
    }

    // Blocked inbound IDS/IPS hits against a host explicitly confirmed
    // WAN-exposed (see ruleTriage.ts's tryExposedHostScanRule doc) —
    // deliberately not signature-restricted like reputation_blocklist:
    // an attacker's target port is arbitrary/unpredictable, so the
    // completeness bar is carried entirely by "every event from this
    // source IP is a blocked ips_alert hit against this specific
    // wanExposed host," tried one host at a time (first full match wins,
    // same pattern as the homelab_service_egress loop below).
    if (!verdict && allowed('exposed_host_scan')) {
      for (const [hostIp, host] of Object.entries(deps.homelabServices ?? {})) {
        if (verdict || !host.wanExposed) continue;
        const exposedCounts = sourceIpEventCounts(
          deps.sinkDb,
          finding.entity_key,
          sinceIso,
          `category = 'ips_alert' AND action = 'blocked' AND dest_ip = ?`,
          [hostIp],
          untilIso
        );
        const exposedVerdict = tryExposedHostScanRule(exposedCounts, { hostLabel: host.label });
        if (exposedVerdict) {
          verdict = exposedVerdict;
          rule = 'exposed_host_scan';
        }
      }
    }
  } else if (finding.entity_type === 'signature') {
    const { category, signature } = splitSignatureKey(finding.entity_key);

    if (allowed('ignored_signature') && isIgnoredSignature(category, signature)) {
      verdict = tryIgnoredSignatureRule();
      rule = 'ignored_signature';
    }

    if (
      !verdict &&
      allowed('operational_noise') &&
      NON_SECURITY_OPERATIONAL_CATEGORIES.includes(category)
    ) {
      // A new_signature finding's events are already scoped to this exact
      // (category, signature) pair by the query below, so once `category`
      // itself is operational, every backing event trivially matches —
      // the `1=1` predicate just gets the total/matching counts symmetric
      // with the other rules' completeness check (and guards the total=0
      // case via isComplete).
      const opCounts = signatureEventCounts(
        deps.sinkDb,
        category,
        signature,
        sinceIso,
        '1=1',
        [],
        untilIso
      );
      verdict = tryOperationalNoiseRule(opCounts);
      if (verdict) rule = 'operational_noise';
    }

    if (
      !verdict &&
      allowed('low_signal_category') &&
      LOW_SIGNAL_SYSTEM_CATEGORIES.includes(category)
    ) {
      // Same trivial-completeness shape as the operational-noise check above
      // (category already pins every backing event), just against a
      // different, non-operational category set. See ruleTriage.ts for why
      // 'audit' is deliberately excluded from this list.
      const lowSignalCounts = signatureEventCounts(
        deps.sinkDb,
        category,
        signature,
        sinceIso,
        '1=1',
        [],
        untilIso
      );
      verdict = tryLowSignalCategoryRule(lowSignalCounts);
      if (verdict) rule = 'low_signal_category';
    }

    if (!verdict && allowed('reputation_blocklist') && category === 'ips_alert' && prefixClause) {
      const blockCounts = signatureEventCounts(
        deps.sinkDb,
        category,
        signature,
        sinceIso,
        `action = 'blocked' AND (${prefixClause})`,
        prefixParams,
        untilIso
      );
      verdict = tryReputationBlocklistRule(blockCounts);
      if (verdict) rule = 'reputation_blocklist';
    }

    // Outbound hits where every backing event's (source_ip, dest_port) pair
    // matches a documented homelab service's own listen port — e.g. a
    // self-hosted P2P client (slskd/Soulseek) whose normal peer traffic on
    // its configured port trips a generic byte-pattern IDS signature. Tried
    // one (host, service) pair at a time since the completeness bar is
    // per-pair; first full match wins, same as the other signature rules.
    if (!verdict && allowed('homelab_service_egress') && category === 'ips_alert') {
      const hostServicePairs = Object.entries(deps.homelabServices ?? {}).flatMap(
        ([hostIp, host]) => host.services.map((service) => ({ hostIp, host, service }))
      );
      for (const { hostIp, host, service } of hostServicePairs) {
        if (verdict) break;
        const counts = signatureEventCounts(
          deps.sinkDb,
          category,
          signature,
          sinceIso,
          `action = 'blocked' AND source_ip = ? AND dest_port = ?`,
          [hostIp, service.port],
          untilIso
        );
        const homelabVerdict = tryHomelabServiceRule(counts, {
          hostLabel: host.label,
          serviceName: service.name,
          serviceDescription: service.description,
          port: service.port,
        });
        if (homelabVerdict) {
          verdict = homelabVerdict;
          rule = 'homelab_service_egress';
        }
      }
    }
  }

  return verdict && rule ? { rule, verdict } : null;
}
