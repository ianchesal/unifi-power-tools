import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { createAnalysisRequestsRouter } from '../../src/api/analysisRequests.js';
import { createAnalysisRequest, recordAiVerdict } from '../../src/db/analysisRequestsStore.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';
import { createUnifiMcpClient } from '../../src/enrichment/unifiMcpClient.js';

function appFor(lensDb: ReturnType<typeof openLensDb>) {
  const app = express();
  app.use(express.json());
  app.use('/api', createAnalysisRequestsRouter(lensDb, createUnifiMcpClient(null), null));
  return app;
}

describe('analysis-requests API', () => {
  it('GET /analysis-requests lists pending requests; ?findingId= includes answered ones', async () => {
    const lensDb = openLensDb(':memory:');
    const a = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '192.0.2.1'));
    const b = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '192.0.2.2'));
    const answered = createAnalysisRequest(lensDb, a.id as number, 't1');
    recordAiVerdict(
      lensDb,
      answered.id,
      { verdict: 'attention', risk_level: 'high', summary: 's', reasoning: 'quarantine the host', recommended_action: 'isolate' },
      't2'
    );
    const pending = createAnalysisRequest(lensDb, b.id as number, 't1');
    const app = appFor(lensDb);

    const forFinding = await request(app).get(`/api/analysis-requests?findingId=${a.id}`);
    expect(forFinding.status).toBe(200);
    expect(forFinding.body).toHaveLength(1);
    expect(forFinding.body[0]).toMatchObject({
      id: answered.id,
      status: 'answered',
      recommendation: 'quarantine the host',
      risk_level: 'high',
    });

    const unfiltered = await request(app).get('/api/analysis-requests');
    expect(unfiltered.status).toBe(200);
    expect(unfiltered.body.map((r: { id: number }) => r.id)).toEqual([pending.id]);
  });

  it('POST /findings/:id/analyze no longer exists (requests are queued by the pipeline)', async () => {
    const lensDb = openLensDb(':memory:');
    const f = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '192.0.2.3'));
    const res = await request(appFor(lensDb)).post(`/api/findings/${f.id}/analyze`);
    expect(res.status).toBe(404);
  });
});
