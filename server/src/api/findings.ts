import { type Request, type Response, Router } from 'express';
import { z } from 'zod';
import type { ClosedBy, Finding } from '../analysis/findings.js';
import { FindingNotFoundError, TransitionError } from '../analysis/findings.js';
import { splitSignatureKey } from '../analysis/newEntity.js';
import { humanClose, humanReopen, reanalyze } from '../analysis/pipeline.js';
import { type AnalysisRequestRow, latestAnsweredAnalyses } from '../db/analysisRequestsStore.js';
import { listHistory } from '../db/findingHistoryStore.js';
import {
  closedCountsSince,
  countFindings,
  type FindingsFilter,
  getFindingById,
  listFindings,
} from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';
import type { SinkDb } from '../db/sinkDb.js';
import {
  eventsForClientMac,
  eventsForSignature,
  eventsForSourceIp,
  latestClientNames,
} from '../db/sinkQueries.js';

const VIEWS = ['open', 'attention', 'triaging', 'closed', 'all'] as const;
const CLOSED_BYS = ['rule', 'ai', 'human', 'system'] as const;

const CloseBody = z.object({
  kind: z.enum(['handled', 'not_concern']),
  note: z.string().optional(),
});
const ReopenBody = z.object({ note: z.string().trim().min(1, 'note is required') });

export type FindingListItem = FindingWithDisplayName & {
  latest_analysis: Omit<AnalysisRequestRow, 'context'> | null;
};

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

  // Attaches each finding's latest answered analysis (minus the bulky
  // `context` bundle, which is for the MCP handoff, not the dashboard).
  function withAnalyses(findings: FindingWithDisplayName[]): FindingListItem[] {
    const latest = latestAnsweredAnalyses(
      lensDb,
      findings.map((f) => f.id as number)
    );
    return findings.map((f) => {
      const row = latest.get(f.id as number);
      if (!row) return { ...f, latest_analysis: null };
      const { context: _context, ...analysis } = row;
      return { ...f, latest_analysis: analysis };
    });
  }

  router.get('/findings', (req, res) => {
    const view = typeof req.query.view === 'string' ? req.query.view : 'open';
    if (!(VIEWS as readonly string[]).includes(view)) {
      res.status(400).json({ error: `view must be one of ${VIEWS.join(', ')}` });
      return;
    }
    const filter: FindingsFilter = { view: view as FindingsFilter['view'] };
    if (typeof req.query.closed_by === 'string') {
      if (!(CLOSED_BYS as readonly string[]).includes(req.query.closed_by)) {
        res.status(400).json({ error: `closed_by must be one of ${CLOSED_BYS.join(', ')}` });
        return;
      }
      filter.closedBy = req.query.closed_by as ClosedBy;
    }
    if (typeof req.query.q === 'string' && req.query.q !== '') filter.q = req.query.q;

    const build = (rows: Finding[]) => withAnalyses(withDisplayNames(sinkDb, rows));

    // limit/offset are opt-in: callers that don't paginate keep getting the
    // full unpaginated array.
    const limitRaw = typeof req.query.limit === 'string' ? Number(req.query.limit) : undefined;
    if (limitRaw === undefined) {
      res.json(build(listFindings(lensDb, filter)));
      return;
    }
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : 20;
    const offsetRaw = typeof req.query.offset === 'string' ? Number(req.query.offset) : 0;
    const offset = Number.isFinite(offsetRaw) && offsetRaw >= 0 ? Math.floor(offsetRaw) : 0;
    res.json({
      items: build(listFindings(lensDb, { ...filter, limit, offset })),
      total: countFindings(lensDb, filter),
    });
  });

  router.get('/findings-summary', (_req, res) => {
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    res.json({
      attention: countFindings(lensDb, { view: 'attention' }),
      triaging: countFindings(lensDb, { view: 'triaging' }),
      closed_last_7d: closedCountsSince(lensDb, since),
    });
  });

  router.get('/findings/:id/history', (req, res) => {
    const id = Number(req.params.id);
    if (!getFindingById(lensDb, id)) {
      res.status(404).json({ error: 'finding not found' });
      return;
    }
    res.json(listHistory(lensDb, id));
  });

  // Shared error mapping for the three state-changing POSTs.
  function act(req: Request, res: Response, run: (id: number, nowIso: string) => Finding): void {
    try {
      res.json(run(Number(req.params.id), new Date().toISOString()));
    } catch (err) {
      if (err instanceof FindingNotFoundError) {
        res.status(404).json({ error: 'finding not found' });
      } else if (err instanceof TransitionError) {
        res.status(409).json({ error: err.message, status: err.from });
      } else {
        throw err;
      }
    }
  }

  router.post('/findings/:id/close', (req, res) => {
    const parsed = CloseBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'kind must be "handled" or "not_concern"' });
      return;
    }
    const { kind, note } = parsed.data;
    act(req, res, (id, now) => humanClose(lensDb, id, kind, note ?? null, now));
  });

  router.post('/findings/:id/reopen', (req, res) => {
    const parsed = ReopenBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'note is required' });
      return;
    }
    act(req, res, (id, now) => humanReopen(lensDb, id, parsed.data.note, now));
  });

  router.post('/findings/:id/reanalyze', (req, res) => {
    act(req, res, (id, now) => reanalyze(lensDb, id, now));
  });

  // Named "activity" rather than "events" — ad blockers and privacy
  // extensions commonly filter request paths containing "events" as an
  // analytics-tracking pattern (see /stats/activity-over-time for the same
  // fix and the root-cause writeup).
  router.get('/findings/:id/activity', (req, res) => {
    const finding = getFindingById(lensDb, Number(req.params.id));
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
