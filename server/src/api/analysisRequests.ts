import { Router } from 'express';
import {
  getAnalysisRequestsForFinding,
  getPendingAnalysisRequests,
} from '../db/analysisRequestsStore.js';
import type { LensDb } from '../db/lensDb.js';
import type { SinkDb } from '../db/sinkDb.js';
import type { HomelabRegistry } from '../enrichment/homelabServices.js';
import type { UnifiMcpClient } from '../enrichment/unifiMcpClient.js';

// Analysis requests are queued by the pipeline and their context is built when
// a Claude Code session fetches them (see mcp/context.ts), so this router is
// read-only.
export function createAnalysisRequestsRouter(
  lensDb: LensDb,
  _unifiMcp: UnifiMcpClient,
  _sinkDb: SinkDb | null,
  _homelabServices: HomelabRegistry = {}
): Router {
  const router = Router();

  router.get('/analysis-requests', (req, res) => {
    const findingId = req.query.findingId ? Number(req.query.findingId) : undefined;
    if (findingId !== undefined) {
      res.json(getAnalysisRequestsForFinding(lensDb, findingId));
      return;
    }
    res.json(getPendingAnalysisRequests(lensDb));
  });

  return router;
}
