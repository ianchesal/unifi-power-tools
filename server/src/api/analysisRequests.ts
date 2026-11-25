import { Router } from 'express';
import {
  getAnalysisRequestsForFinding,
  getPendingAnalysisRequests,
  getQueueStats,
} from '../db/analysisRequestsStore.js';
import type { LensDb } from '../db/lensDb.js';

// `context` is the MCP handoff bundle; the dashboard never needs it.
function stripContext<T extends { context?: unknown }>(row: T): Omit<T, 'context'> {
  const { context: _context, ...rest } = row;
  return rest;
}

// Analysis requests are queued by the pipeline and their context is built when
// a Claude Code session fetches them (see mcp/context.ts), so this router is
// read-only.
export function createAnalysisRequestsRouter(lensDb: LensDb): Router {
  const router = Router();

  router.get('/analysis-requests', (req, res) => {
    const findingId = req.query.findingId ? Number(req.query.findingId) : undefined;
    if (findingId !== undefined) {
      res.json(getAnalysisRequestsForFinding(lensDb, findingId).map(stripContext));
      return;
    }
    res.json(getPendingAnalysisRequests(lensDb).map(stripContext));
  });

  router.get('/queue', (_req, res) => {
    res.json(getQueueStats(lensDb));
  });

  return router;
}
