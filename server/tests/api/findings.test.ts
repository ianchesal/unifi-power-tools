import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { createAnalysisRequestsRouter } from '../../src/api/analysisRequests.js';
import { createAnalysisRequest, recordAiVerdict } from '../../src/db/analysisRequestsStore.js';
import { updateFindingState, upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';
import type { SinkDb } from '../../src/db/sinkDb.js';
import { createFindingsRouter } from '../../src/api/findings.js';

function seededSinkDb(
  rows: { received_at: string; category: string; signature?: string | null; source_ip?: string | null; action?: string | null }[]
): SinkDb {
  const conn = new DatabaseSync(':memory:');
  conn.exec(
    `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
     category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
     dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
     signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER)`
  );
  const stmt = conn.prepare(
    `INSERT INTO events (received_at, category, signature, source_ip, action, raw, parsed)
     VALUES (?, ?, ?, ?, ?, 'raw-line', 1)`
  );
  for (const r of rows) stmt.run(r.received_at, r.category, r.signature ?? null, r.source_ip ?? null, r.action ?? null);
  return { conn };
}

type Db = ReturnType<typeof openLensDb>;

function makeFinding(db: Db, ip: string, state: Parameters<typeof updateFindingState>[2] = {}) {
  const f = upsertFinding(db, applyTrigger(null, 'internal_source', 't0', 'source_ip', ip));
  return state && Object.keys(state).length
    ? (updateFindingState(db, f.id as number, state) as typeof f)
    : f;
}

const closed = (by: 'rule' | 'ai' | 'human' | 'system', reason: string, at = new Date().toISOString()) => ({
  status: 'closed' as const,
  closed_by: by,
  closed_reason: reason,
  closed_at: at,
});

function appFor(db: Db, sinkDb: SinkDb | null = null) {
  const app = express();
  app.use(express.json());
  app.use('/api', createFindingsRouter(db, sinkDb));
  app.use('/api', createAnalysisRequestsRouter(db));
  return app;
}

describe('findings API', () => {
  it('GET /api/findings defaults to open work and embeds latest_analysis', async () => {
    const db = openLensDb(':memory:');
    const att = makeFinding(db, '192.0.2.1', { status: 'attention' });
    makeFinding(db, '192.0.2.2'); // triaging
    makeFinding(db, '192.0.2.3', closed('rule', 'noise'));
    const req = createAnalysisRequest(db, att.id as number, 't1');
    recordAiVerdict(
      db,
      req.id,
      { verdict: 'attention', risk_level: 'high', summary: 'do X', reasoning: 'because' },
      't2'
    );

    const res = await request(appFor(db)).get('/api/findings');
    expect(res.status).toBe(200);
    expect(res.body.map((f: { status: string }) => f.status).sort()).toEqual(['attention', 'triaging']);
    const a = res.body.find((f: { status: string }) => f.status === 'attention');
    expect(a.latest_analysis.summary).toBe('do X');
    expect(a.latest_analysis).not.toHaveProperty('context');
    const t = res.body.find((f: { status: string }) => f.status === 'triaging');
    expect(t.latest_analysis).toBeNull();
  });

  it('?view=closed&closed_by=rule&q= filters; invalid view/closed_by → 400', async () => {
    const db = openLensDb(':memory:');
    makeFinding(db, '192.0.2.1', closed('rule', 'WAN noise'));
    makeFinding(db, '192.0.2.2', closed('rule', 'blocklist hit'));
    makeFinding(db, '192.0.2.3', closed('human', 'WAN noise'));
    makeFinding(db, '192.0.2.4');
    const app = appFor(db);

    const all = await request(app).get('/api/findings?view=closed');
    expect(all.body).toHaveLength(3);
    const byRule = await request(app).get('/api/findings?view=closed&closed_by=rule');
    expect(byRule.body).toHaveLength(2);
    const q = await request(app).get('/api/findings?view=closed&closed_by=rule&q=wan');
    expect(q.body.map((f: { entity_key: string }) => f.entity_key)).toEqual(['192.0.2.1']);

    expect((await request(app).get('/api/findings?view=bogus')).status).toBe(400);
    expect((await request(app).get('/api/findings?closed_by=bogus')).status).toBe(400);
  });

  it('paginates when limit/offset are passed, returning items + total', async () => {
    const db = openLensDb(':memory:');
    for (let i = 0; i < 5; i++) makeFinding(db, `10.0.0.${i}`);
    const app = appFor(db);

    const page1 = await request(app).get('/api/findings?limit=2&offset=0');
    expect(page1.body.total).toBe(5);
    expect(page1.body.items).toHaveLength(2);
    const page3 = await request(app).get('/api/findings?limit=2&offset=4');
    expect(page3.body.items).toHaveLength(1);
  });

  it('POST close on an attention finding closes it with the note', async () => {
    const db = openLensDb(':memory:');
    const f = makeFinding(db, '192.0.2.1', { status: 'attention' });
    const res = await request(appFor(db))
      .post(`/api/findings/${f.id}/close`)
      .send({ kind: 'handled', note: 'blocked at the firewall' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      status: 'closed',
      closed_by: 'human',
      closed_reason: 'blocked at the firewall',
    });
  });

  it('POST close on a triaging finding → 409 naming the status; bad body → 400', async () => {
    const db = openLensDb(':memory:');
    const triaging = makeFinding(db, '192.0.2.1');
    const app = appFor(db);
    const res = await request(app).post(`/api/findings/${triaging.id}/close`).send({ kind: 'handled' });
    expect(res.status).toBe(409);
    expect(res.body).toMatchObject({ status: 'triaging' });
    expect(res.body.error).toMatch(/triaging/);

    const bad = await request(app).post(`/api/findings/${triaging.id}/close`).send({ kind: 'bogus' });
    expect(bad.status).toBe(400);
  });

  it('POST reopen requires a non-blank note (400) and moves closed → attention', async () => {
    const db = openLensDb(':memory:');
    const f = makeFinding(db, '192.0.2.1', closed('rule', 'noise'));
    const app = appFor(db);

    expect((await request(app).post(`/api/findings/${f.id}/reopen`).send({})).status).toBe(400);
    expect((await request(app).post(`/api/findings/${f.id}/reopen`).send({ note: '   ' })).status).toBe(400);

    const ok = await request(app).post(`/api/findings/${f.id}/reopen`).send({ note: 'still seeing it' });
    expect(ok.status).toBe(200);
    expect(ok.body.status).toBe('attention');
  });

  it('list items embed latest_reopen_note: the most recent reopen note, else null', async () => {
    const db = openLensDb(':memory:');
    const f = makeFinding(db, '192.0.2.1', closed('rule', 'noise'));
    makeFinding(db, '192.0.2.2', { status: 'attention' });
    const app = appFor(db);
    expect((await request(app).post(`/api/findings/${f.id}/reopen`).send({ note: 'first' })).status).toBe(200);
    expect(
      (await request(app).post(`/api/findings/${f.id}/close`).send({ kind: 'handled' })).status
    ).toBe(200);
    expect((await request(app).post(`/api/findings/${f.id}/reopen`).send({ note: 'block did not take' })).status).toBe(200);

    const byIp = (rows: { entity_key: string; latest_reopen_note: string | null }[], ip: string) =>
      rows.find((r) => r.entity_key === ip)?.latest_reopen_note;
    const list = await request(app).get('/api/findings?view=attention');
    expect(byIp(list.body, '192.0.2.1')).toBe('block did not take');
    expect(byIp(list.body, '192.0.2.2')).toBeNull();
    const paged = await request(app).get('/api/findings?view=attention&limit=10');
    expect(byIp(paged.body.items, '192.0.2.1')).toBe('block did not take');
  });

  it('POST reanalyze moves closed → triaging and queues one pending request', async () => {
    const db = openLensDb(':memory:');
    const f = makeFinding(db, '192.0.2.1', closed('human', 'ok'));
    const app = appFor(db);
    const res = await request(app).post(`/api/findings/${f.id}/reanalyze`);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('triaging');
    const pending = await request(app).get(`/api/analysis-requests?findingId=${f.id}`);
    expect(pending.body.filter((r: { status: string }) => r.status === 'pending')).toHaveLength(1);
  });

  it('POST to an unknown id → 404', async () => {
    const app = appFor(openLensDb(':memory:'));
    expect((await request(app).post('/api/findings/999/close').send({ kind: 'handled' })).status).toBe(404);
    expect((await request(app).post('/api/findings/999/reopen').send({ note: 'x' })).status).toBe(404);
    expect((await request(app).post('/api/findings/999/reanalyze')).status).toBe(404);
    expect((await request(app).get('/api/findings/999/history')).status).toBe(404);
  });

  it('GET history returns the timeline in order', async () => {
    const db = openLensDb(':memory:');
    const f = makeFinding(db, '192.0.2.1', { status: 'attention' });
    const app = appFor(db);
    await request(app).post(`/api/findings/${f.id}/close`).send({ kind: 'not_concern' });
    await request(app).post(`/api/findings/${f.id}/reopen`).send({ note: 'again' });
    const res = await request(app).get(`/api/findings/${f.id}/history`);
    expect(res.status).toBe(200);
    expect(res.body.map((h: { kind: string }) => h.kind)).toEqual([
      'human_closed_not_concern',
      'human_reopened',
    ]);
  });

  it('GET /api/findings-summary counts attention, triaging and closed in last 7 days by closed_by', async () => {
    const db = openLensDb(':memory:');
    makeFinding(db, '192.0.2.1', { status: 'attention' });
    makeFinding(db, '192.0.2.2', { status: 'attention' });
    makeFinding(db, '192.0.2.3');
    makeFinding(db, '192.0.2.4', closed('rule', 'r'));
    makeFinding(db, '192.0.2.5', closed('ai', 'a'));
    makeFinding(db, '192.0.2.6', closed('rule', 'old', '2020-01-01T00:00:00.000Z'));
    const res = await request(appFor(db)).get('/api/findings-summary');
    expect(res.body).toEqual({
      attention: 2,
      triaging: 1,
      closed_last_7d: { rule: 1, ai: 1, human: 0, system: 0 },
    });
  });

  it('GET /api/queue reports count, oldest pending and last AI answer', async () => {
    const db = openLensDb(':memory:');
    const a = makeFinding(db, '192.0.2.1');
    const b = makeFinding(db, '192.0.2.2');
    const answered = createAnalysisRequest(db, a.id as number, '2026-11-25T00:00:00.000Z');
    recordAiVerdict(
      db,
      answered.id,
      { verdict: 'close', risk_level: 'low', summary: 's', reasoning: 'r' },
      '2026-11-25T01:00:00.000Z'
    );
    createAnalysisRequest(db, b.id as number, '2026-11-25T02:00:00.000Z');
    const res = await request(appFor(db)).get('/api/queue');
    expect(res.body).toEqual({
      count: 1,
      oldest_created_at: '2026-11-25T02:00:00.000Z',
      last_answered_at: '2026-11-25T01:00:00.000Z',
    });
  });

  it('POST /api/findings/:id/status and /analyze are gone (404)', async () => {
    const db = openLensDb(':memory:');
    const f = makeFinding(db, '192.0.2.1');
    const app = appFor(db);
    expect((await request(app).post(`/api/findings/${f.id}/status`).send({ status: 'dismissed' })).status).toBe(404);
    expect((await request(app).post(`/api/findings/${f.id}/analyze`)).status).toBe(404);
  });

  it('list, summary and queue work with sinkDb = null', async () => {
    const app = appFor(openLensDb(':memory:'), null);
    expect((await request(app).get('/api/findings')).status).toBe(200);
    expect((await request(app).get('/api/findings-summary')).status).toBe(200);
    expect((await request(app).get('/api/queue')).status).toBe(200);
  });
});

describe('GET /api/findings/:id/activity', () => {
  it('returns raw events for a source_ip finding', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const sinkDb = seededSinkDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
      { received_at: '2026-08-31T02:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '9.9.9.9', action: 'blocked' },
    ]);

    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb, sinkDb));

    const res = await request(app).get(`/api/findings/${finding.id}/activity`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].source_ip).toBe('1.2.3.4');
  });

  it('returns raw events for a signature finding', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(
      lensDb,
      applyTrigger(null, 'new_signature', 't0', 'signature', 'ips_alert|ET DROP Foo')
    );
    const sinkDb = seededSinkDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
      { received_at: '2026-08-31T02:00:00Z', category: 'ips_alert', signature: 'ET MALWARE Bar', source_ip: '1.2.3.4', action: 'blocked' },
    ]);

    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb, sinkDb));

    const res = await request(app).get(`/api/findings/${finding.id}/activity`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].signature).toBe('ET DROP Foo');
  });

  it('returns 404 for a nonexistent finding', async () => {
    const lensDb = openLensDb(':memory:');
    const sinkDb = seededSinkDb([]);
    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb, sinkDb));

    const res = await request(app).get('/api/findings/999/activity');
    expect(res.status).toBe(404);
  });

  it('returns 503 when the sink DB is unavailable', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb, null));

    const res = await request(app).get(`/api/findings/${finding.id}/activity`);
    expect(res.status).toBe(503);
  });
});

describe('findings API — client findings', () => {
  const MAC = 'aa:aa:aa:aa:aa:01';
  function clientSinkDb(rows: { mac: string; name: string | null; source_ip?: string | null; category?: string }[]): SinkDb {
    const conn = new DatabaseSync(':memory:');
    conn.exec(`CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
  category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
  dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
  signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER,
  source_client_name TEXT, source_client_mac TEXT, dest_client_name TEXT, dest_client_mac TEXT)`);
    const stmt = conn.prepare(
      `INSERT INTO events (received_at, category, signature, source_ip, source_client_mac, source_client_name, raw, parsed)
       VALUES ('2026-11-25T00:00:00Z', ?, 'sig', ?, ?, ?, 'raw-line', 1)`
    );
    for (const r of rows) stmt.run(r.category ?? 'ips_alert', r.source_ip ?? null, r.mac, r.name);
    return { conn };
  }
  function appWith(sinkDb: SinkDb | null) {
    const lensDb = openLensDb(':memory:');
    const client = upsertFinding(lensDb, applyTrigger(null, 'new_client', 't0', 'client', MAC));
    upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb, sinkDb));
    return { app, client };
  }

  it('attaches display_name to client findings in both response shapes', async () => {
    const { app } = appWith(clientSinkDb([{ mac: MAC, name: 'tranquility' }]));

    const bare = await request(app).get('/api/findings');
    const clientItem = bare.body.find((f: { entity_type: string }) => f.entity_type === 'client');
    const ipItem = bare.body.find((f: { entity_type: string }) => f.entity_type === 'source_ip');
    expect(clientItem.display_name).toBe('tranquility');
    expect(ipItem).not.toHaveProperty('display_name');

    const paged = await request(app).get('/api/findings?limit=10');
    const pagedClient = paged.body.items.find((f: { entity_type: string }) => f.entity_type === 'client');
    expect(pagedClient.display_name).toBe('tranquility');
  });

  it('returns display_name null when the sink is unavailable', async () => {
    const { app } = appWith(null);
    const res = await request(app).get('/api/findings');
    expect(res.status).toBe(200);
    expect(res.body.find((f: { entity_type: string }) => f.entity_type === 'client').display_name).toBeNull();
  });

  it('returns display_name null when the name lookup fails (pre-v1.0.3 sink)', async () => {
    const { app } = appWith(seededSinkDb([]));
    const res = await request(app).get('/api/findings');
    expect(res.status).toBe(200);
    expect(res.body.find((f: { entity_type: string }) => f.entity_type === 'client').display_name).toBeNull();
  });

  it('GET /findings/:id/activity returns events for a client finding by MAC', async () => {
    const { app, client } = appWith(
      clientSinkDb([
        { mac: MAC, name: 'tranquility' },
        { mac: MAC, name: 'tranquility', category: 'firewall_block' },
        { mac: 'aa:aa:aa:aa:aa:09', name: 'other' },
      ])
    );
    const res = await request(app).get(`/api/findings/${client.id}/activity`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
    for (const e of res.body) expect(e.source_client_mac).toBe(MAC);
  });
});
