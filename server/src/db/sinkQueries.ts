import { CLIENT_SECURITY_CATEGORIES, IGNORED_SIGNATURE_KEYS } from '../analysis/newEntity.js';
import type { SinkDb } from './sinkDb.js';

export interface StoredEvent {
  id: number;
  received_at: string;
  category: string;
  severity: number | null;
  source_ip: string | null;
  dest_ip: string | null;
  dest_port: number | null;
  action: string | null;
  signature: string | null;
  message: string | null;
  raw: string;
}

export function listEvents(db: SinkDb, opts: { since?: string; limit?: number }): StoredEvent[] {
  const clauses: string[] = [];
  const params: (string | number)[] = [];
  if (opts.since) {
    clauses.push('received_at >= ?');
    params.push(opts.since);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const limit = Math.min(opts.limit ?? 100, 500);
  return db.conn
    .prepare(
      `SELECT id, received_at, category, severity, source_ip, dest_ip, dest_port, signature, message, raw
       FROM events ${where} ORDER BY received_at DESC LIMIT ?`
    )
    .all(...params, limit) as unknown as StoredEvent[];
}

// Recent raw events for a given source IP, most-recent first. Used as LLM
// analysis context (spec: "relevant recent raw events pulled from events.db
// as context") — capped low since this is prompt context, not a data dump.
export function eventsForSourceIp(db: SinkDb, sourceIp: string, limit = 20): StoredEvent[] {
  return db.conn
    .prepare(
      `SELECT id, received_at, category, severity, source_ip, dest_ip, dest_port, action, signature, message, raw
       FROM events WHERE source_ip = ? ORDER BY received_at DESC LIMIT ?`
    )
    .all(sourceIp, limit) as unknown as StoredEvent[];
}

// Recent raw events for a given (category, signature) pair, most-recent first.
export function eventsForSignature(
  db: SinkDb,
  category: string,
  signature: string,
  limit = 20
): StoredEvent[] {
  return db.conn
    .prepare(
      `SELECT id, received_at, category, severity, source_ip, dest_ip, dest_port, action, signature, message, raw
       FROM events WHERE category = ? AND signature = ? ORDER BY received_at DESC LIMIT ?`
    )
    .all(category, signature, limit) as unknown as StoredEvent[];
}

export function eventsOverTime(
  db: SinkDb,
  opts: { sinceDays: number }
): { day: string; category: string; count: number }[] {
  return db.conn
    .prepare(
      `SELECT date(received_at) as day, category, COUNT(*) as count
       FROM events WHERE received_at >= datetime('now', ?)
       GROUP BY day, category ORDER BY day ASC`
    )
    .all(`-${opts.sinceDays} days`) as unknown as {
    day: string;
    category: string;
    count: number;
  }[];
}

export function topSignatures(
  db: SinkDb,
  opts: { sinceDays: number; limit: number }
): { signature: string; count: number }[] {
  return db.conn
    .prepare(
      `SELECT signature, COUNT(*) as count FROM events
       WHERE received_at >= datetime('now', ?) AND signature IS NOT NULL AND signature != ''
       GROUP BY signature ORDER BY count DESC LIMIT ?`
    )
    .all(`-${opts.sinceDays} days`, opts.limit) as unknown as {
    signature: string;
    count: number;
  }[];
}

export function topSourceIps(
  db: SinkDb,
  opts: { sinceDays: number; limit: number }
): { source_ip: string; count: number }[] {
  return db.conn
    .prepare(
      `SELECT source_ip, COUNT(*) as count FROM events
       WHERE received_at >= datetime('now', ?) AND source_ip IS NOT NULL
       GROUP BY source_ip ORDER BY count DESC LIMIT ?`
    )
    .all(`-${opts.sinceDays} days`, opts.limit) as unknown as {
    source_ip: string;
    count: number;
  }[];
}

export function severityDistribution(
  db: SinkDb,
  opts: { sinceDays: number }
): { severity: number | null; count: number }[] {
  return db.conn
    .prepare(
      `SELECT severity, COUNT(*) as count FROM events
       WHERE received_at >= datetime('now', ?)
       GROUP BY severity ORDER BY severity ASC`
    )
    .all(`-${opts.sinceDays} days`) as unknown as { severity: number | null; count: number }[];
}

export interface EntityEventCounts {
  total: number;
  matching: number;
}

// SQL-level completeness check for rule-based triage: counts every event for
// the entity in the window (`total`) alongside only those also satisfying
// `matchingWhereSql` (`matching`). Deliberately does not reuse the LIMIT-20
// fetchers above — those are sized for LLM prompt context, and a burst of
// more than 20 events could otherwise let the most recent 20 stand in for
// "every event" and hide a non-matching event outside the cap.
export function sourceIpEventCounts(
  db: SinkDb,
  sourceIp: string,
  sinceIso: string,
  matchingWhereSql: string,
  matchingParams: (string | number)[] = [],
  untilIso?: string
): EntityEventCounts {
  const windowSql = untilIso ? 'received_at >= ? AND received_at < ?' : 'received_at >= ?';
  const windowParams = untilIso ? [sinceIso, untilIso] : [sinceIso];
  const total = (
    db.conn
      .prepare(`SELECT COUNT(*) as n FROM events WHERE source_ip = ? AND ${windowSql}`)
      .get(sourceIp, ...windowParams) as { n: number }
  ).n;
  const matching = (
    db.conn
      .prepare(
        `SELECT COUNT(*) as n FROM events WHERE source_ip = ? AND ${windowSql} AND (${matchingWhereSql})`
      )
      .get(sourceIp, ...windowParams, ...matchingParams) as { n: number }
  ).n;
  return { total, matching };
}

export function signatureEventCounts(
  db: SinkDb,
  category: string,
  signature: string,
  sinceIso: string,
  matchingWhereSql: string,
  matchingParams: (string | number)[] = [],
  untilIso?: string
): EntityEventCounts {
  const windowSql = untilIso ? 'received_at >= ? AND received_at < ?' : 'received_at >= ?';
  const windowParams = untilIso ? [sinceIso, untilIso] : [sinceIso];
  const total = (
    db.conn
      .prepare(
        `SELECT COUNT(*) as n FROM events WHERE category = ? AND signature = ? AND ${windowSql}`
      )
      .get(category, signature, ...windowParams) as { n: number }
  ).n;
  const matching = (
    db.conn
      .prepare(
        `SELECT COUNT(*) as n FROM events WHERE category = ? AND signature = ? AND ${windowSql} AND (${matchingWhereSql})`
      )
      .get(category, signature, ...windowParams, ...matchingParams) as { n: number }
  ).n;
  return { total, matching };
}

// Unbounded (no LIMIT) category+message rows for a source IP in the window.
// Used only by the admin-audit-login triage rule, whose match condition
// (regex over free text) can't be expressed as a SQL predicate the way the
// other rules' counts above are — audit-category volume per entity per
// window is inherently small, so fetching all of it is cheap and, unlike a
// capped fetch, doesn't risk missing a non-matching event.
export function auditCandidateEvents(
  db: SinkDb,
  sourceIp: string,
  sinceIso: string,
  untilIso?: string
): { category: string; message: string | null }[] {
  if (untilIso) {
    return db.conn
      .prepare(
        'SELECT category, message FROM events WHERE source_ip = ? AND received_at >= ? AND received_at < ?'
      )
      .all(sourceIp, sinceIso, untilIso) as unknown as {
      category: string;
      message: string | null;
    }[];
  }
  return db.conn
    .prepare('SELECT category, message FROM events WHERE source_ip = ? AND received_at >= ?')
    .all(sourceIp, sinceIso) as unknown as { category: string; message: string | null }[];
}

// ---------------------------------------------------------------------------
// Client-only queries (sink >= v1.0.3). These are the ONLY queries that may
// reference the source_client_* / dest_client_* columns: every existing query
// above deliberately leaves them out, so a sink older than v1.0.3 loses only
// client features (failing inside the client runCheck / API branch) while IP
// and signature analysis keeps working. See
// docs/superpowers/specs/2026-11-25-client-entities-design.md.
// ---------------------------------------------------------------------------

export interface ClientStoredEvent extends StoredEvent {
  source_client_name: string | null;
  source_client_mac: string | null;
  dest_client_name: string | null;
  dest_client_mac: string | null;
}

// "Client-only Security event": UniFi named the LAN host by MAC with no IP,
// in one of the categories the sink maps UNIFIcategory = 'Security' to.
// Ignored signatures are excluded the same way the runner excludes them.
function clientOnlyWhere(): { sql: string; params: string[] } {
  const ignored = [...IGNORED_SIGNATURE_KEYS];
  const categoryPlaceholders = CLIENT_SECURITY_CATEGORIES.map(() => '?').join(', ');
  const ignoredSql = ignored.length
    ? ` AND (category || '|' || COALESCE(signature, '')) NOT IN (${ignored.map(() => '?').join(', ')})`
    : '';
  return {
    sql: `source_ip IS NULL AND source_client_mac IS NOT NULL AND category IN (${categoryPlaceholders})${ignoredSql}`,
    params: [...CLIENT_SECURITY_CATEGORIES, ...ignored],
  };
}

export function allClientMacs(db: SinkDb): string[] {
  const where = clientOnlyWhere();
  const rows = db.conn
    .prepare(`SELECT DISTINCT source_client_mac AS mac FROM events WHERE ${where.sql}`)
    .all(...where.params) as { mac: string }[];
  return rows.map((r) => r.mac);
}

export function clientMacsSince(db: SinkDb, sinceIso: string): string[] {
  const where = clientOnlyWhere();
  const rows = db.conn
    .prepare(
      `SELECT DISTINCT source_client_mac AS mac FROM events WHERE received_at >= ? AND ${where.sql}`
    )
    .all(sinceIso, ...where.params) as { mac: string }[];
  return rows.map((r) => r.mac);
}

export function clientDayCounts(db: SinkDb, sinceIso: string): { mac: string; days: number }[] {
  const where = clientOnlyWhere();
  return db.conn
    .prepare(
      `SELECT source_client_mac AS mac, COUNT(DISTINCT date(received_at)) AS days FROM events
       WHERE received_at >= ? AND ${where.sql} GROUP BY source_client_mac`
    )
    .all(sinceIso, ...where.params) as { mac: string; days: number }[];
}

// Display-only: the most recent non-null name seen for each MAC on any row
// (not just client-only ones — a name observed alongside an IP is still the
// best label for the host). One row per MAC: SQLite's bare-column rule takes
// source_client_name from the row that supplies MAX(received_at), so a chatty
// client (thousands of C2 keepalives) doesn't ship every row to JS on each
// dashboard refresh.
export function latestClientNames(db: SinkDb, macs: string[]): Map<string, string> {
  if (macs.length === 0) return new Map();
  const rows = db.conn
    .prepare(
      `SELECT source_client_mac AS mac, source_client_name AS name, MAX(received_at) AS latest
       FROM events
       WHERE source_client_mac IN (${macs.map(() => '?').join(', ')}) AND source_client_name IS NOT NULL
       GROUP BY source_client_mac`
    )
    .all(...macs) as { mac: string; name: string }[];
  return new Map(rows.map((r) => [r.mac, r.name]));
}

export function eventsForClientMac(db: SinkDb, mac: string, limit = 20): ClientStoredEvent[] {
  const where = clientOnlyWhere();
  return db.conn
    .prepare(
      `SELECT id, received_at, category, severity, source_ip, dest_ip, dest_port, action, signature, message, raw,
              source_client_name, source_client_mac, dest_client_name, dest_client_mac
       FROM events WHERE source_client_mac = ? AND ${where.sql} ORDER BY received_at DESC LIMIT ?`
    )
    .all(mac, ...where.params, limit) as unknown as ClientStoredEvent[];
}
