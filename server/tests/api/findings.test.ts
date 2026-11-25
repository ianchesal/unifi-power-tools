import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
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

describe('findings API', () => {
  it('GET /api/findings lists findings, POST /:id/status updates status', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));

    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb, null));

    const listRes = await request(app).get('/api/findings');
    expect(listRes.status).toBe(200);
    expect(listRes.body).toHaveLength(1);

    const updateRes = await request(app)
      .post(`/api/findings/${finding.id}/status`)
      .send({ status: 'acknowledged' });
    expect(updateRes.status).toBe(200);
    expect(updateRes.body.status).toBe('acknowledged');
  });

  it('excludes dismissed/resolved findings by default, but includes them when explicitly requested', async () => {
    const lensDb = openLensDb(':memory:');
    const active = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.1.1.1'));
    const dismissed = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '2.2.2.2'));

    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb, null));

    await request(app).post(`/api/findings/${dismissed.id}/status`).send({ status: 'dismissed' });

    const defaultRes = await request(app).get('/api/findings');
    expect(defaultRes.status).toBe(200);
    const defaultIds = defaultRes.body.map((f: { id: number }) => f.id);
    expect(defaultIds).toContain(active.id);
    expect(defaultIds).not.toContain(dismissed.id);

    const explicitRes = await request(app).get('/api/findings?status=dismissed');
    expect(explicitRes.status).toBe(200);
    const explicitIds = explicitRes.body.map((f: { id: number }) => f.id);
    expect(explicitIds).toEqual([dismissed.id]);
  });

  it('paginates when limit/offset are passed, returning items + total', async () => {
    const lensDb = openLensDb(':memory:');
    for (let i = 0; i < 5; i++) {
      upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', `10.0.0.${i}`));
    }

    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb, null));

    const page1 = await request(app).get('/api/findings?limit=2&offset=0');
    expect(page1.status).toBe(200);
    expect(page1.body.total).toBe(5);
    expect(page1.body.items).toHaveLength(2);

    const page3 = await request(app).get('/api/findings?limit=2&offset=4');
    expect(page3.status).toBe(200);
    expect(page3.body.total).toBe(5);
    expect(page3.body.items).toHaveLength(1);
  });

  it('rejects an invalid status', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb, null));

    const res = await request(app).post(`/api/findings/${finding.id}/status`).send({ status: 'bogus' });
    expect(res.status).toBe(400);
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
