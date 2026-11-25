import { Router } from 'express';
import { z } from 'zod';
import type { Finding } from '../analysis/findings.js';
import { splitSignatureKey } from '../analysis/newEntity.js';
import { countFindings, listFindings, setFindingStatus } from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';
import type { SinkDb } from '../db/sinkDb.js';
import {
  eventsForClientMac,
  eventsForSignature,
  eventsForSourceIp,
  latestClientNames,
} from '../db/sinkQueries.js';

const StatusUpdate = z.object({
  status: z.enum(['acknowledged', 'dismissed']),
});

export type FindingWithDisplayName = Finding & { display_name?: string | null };

// Attaches a human-readable `display_name` to client findings: the most recent
// non-null source_client_name the sink has for that MAC, looked up per request
// (never stored, so a renamed client shows its current name). Non-client
// findings are returned without the key. With no sink, or if the lookup fails
// (e.g. a pre-v1.0.3 sink without the client columns), client findings get
// `display_name: null` rather than failing the request.
export function withDisplayNames(
  sinkDb: SinkDb | null,
  findings: Finding[]
): FindingWithDisplayName[] {
  const macs = findings.filter((f) => f.entity_type === 'client').map((f) => f.entity_key);
  if (macs.length === 0) return findings;
  let names = new Map<string, string>();
  if (sinkDb) {
    try {
      names = latestClientNames(sinkDb, macs);
    } catch (err) {
      console.error('Client display-name lookup failed:', err);
    }
  }
  return findings.map((f) =>
    f.entity_type === 'client' ? { ...f, display_name: names.get(f.entity_key) ?? null } : f
  );
}

export function createFindingsRouter(lensDb: LensDb, sinkDb: SinkDb | null): Router {
  const router = Router();

  router.get('/findings', (req, res) => {
    const status = typeof req.query.status === 'string' ? req.query.status : undefined;
    // Default view excludes dismissed/resolved findings — with new_source_ip a
    // permanent, never-auto-resolving trigger, an unfiltered list only grows.
    // Callers that explicitly want dismissed/resolved rows can ask via ?status=,
    // or ?status=all for every finding regardless of status.
    const filter =
      status === 'all'
        ? {}
        : status
          ? { status: status as never }
          : { excludeStatuses: ['dismissed', 'resolved'] as never };

    // limit/offset are opt-in: callers that don't paginate (e.g. the KPI
    // summary, which needs every open finding to compute counts) keep
    // getting the full unpaginated array they always have.
    const limitRaw = typeof req.query.limit === 'string' ? Number(req.query.limit) : undefined;
    if (limitRaw === undefined) {
      res.json(withDisplayNames(sinkDb, listFindings(lensDb, filter)));
      return;
    }
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : 20;
    const offsetRaw = typeof req.query.offset === 'string' ? Number(req.query.offset) : 0;
    const offset = Number.isFinite(offsetRaw) && offsetRaw >= 0 ? Math.floor(offsetRaw) : 0;
    res.json({
      items: withDisplayNames(sinkDb, listFindings(lensDb, { ...filter, limit, offset })),
      total: countFindings(lensDb, filter),
    });
  });

  router.post('/findings/:id/status', (req, res) => {
    const parsed = StatusUpdate.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'status must be "acknowledged" or "dismissed"' });
      return;
    }
    const updated = setFindingStatus(lensDb, Number(req.params.id), parsed.data.status);
    if (!updated) {
      res.status(404).json({ error: 'finding not found' });
      return;
    }
    res.json(updated);
  });

  // Named "activity" rather than "events" — ad blockers and privacy
  // extensions commonly filter request paths containing "events" as an
  // analytics-tracking pattern (see /stats/activity-over-time for the same
  // fix and the root-cause writeup).
  router.get('/findings/:id/activity', (req, res) => {
    const finding = listFindings(lensDb, {}).find((f) => f.id === Number(req.params.id));
    if (!finding) {
      res.status(404).json({ error: 'finding not found' });
      return;
    }
    if (!sinkDb) {
      res.status(503).json({ error: 'Sink DB is unavailable.' });
      return;
    }
    if (finding.entity_type === 'source_ip') {
      res.json(eventsForSourceIp(sinkDb, finding.entity_key));
      return;
    }
    if (finding.entity_type === 'client') {
      res.json(eventsForClientMac(sinkDb, finding.entity_key));
      return;
    }
    const { category, signature } = splitSignatureKey(finding.entity_key);
    res.json(eventsForSignature(sinkDb, category, signature));
  });

  return router;
}
