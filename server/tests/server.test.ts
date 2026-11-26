import request from 'supertest';
import { describe, expect, it } from 'vitest';
import type { RunnerDeps } from '../src/analysis/runner.js';
import type { Config } from '../src/config.js';
import { type EventsDb, openEventsDb } from '../src/db/eventsDb.js';
import { openLensDb } from '../src/db/lensDb.js';
import { type AppDeps, createApp } from '../src/server.js';

export const baseConfig = {
  port: 3002,
  host: '127.0.0.1',
  eventsDbPath: ':memory:',
  lensDbPath: ':memory:',
  lanCidrs: [],
  unifiMcpServerUrl: null,
  unifiMcpServerToken: null,
  logLevel: 'error' as const,
  mcpSecret: 'test-secret',
  trustedAdminNames: [],
  safeSignaturePrefixes: ['ET DROP'],
  homelabServicesPath: '/nonexistent/homelab-services.json',
  retentionDays: 90,
  syslogUdpPort: 10514,
  syslogBindAddress: '127.0.0.1',
  maxMessageBytes: 16384,
} as unknown as Config;

const boundListener = { bound: () => true, droppedCount: () => 0 };

function deps(overrides: Partial<AppDeps> = {}): AppDeps {
  const lensDb = openLensDb(':memory:');
  const eventsDb: EventsDb = openEventsDb(':memory:').reader;
  const runnerDeps: RunnerDeps = {
    eventsDb,
    lensDb,
    lanCidrs: [],
    trustedAdminNames: [],
    safeSignaturePrefixes: ['ET DROP'],
    homelabServices: {},
  };
  return { eventsDb, lensDb, runnerDeps, listener: boundListener, ...overrides };
}

describe('createApp /health', () => {
  it('reports ok with a bound listener and a readable events DB', async () => {
    const res = await request(createApp(deps(), baseConfig)).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      status: 'ok',
      syslog: { bound: true, droppedMessages: 0 },
      eventsDb: 'ok',
    });
  });

  it('reports degraded when the listener is not bound', async () => {
    const app = createApp(
      deps({ listener: { bound: () => false, droppedCount: () => 3 } }),
      baseConfig
    );
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      status: 'degraded',
      syslog: { bound: false, droppedMessages: 3 },
      eventsDb: 'ok',
    });
  });

  it('reports eventsDb error when SELECT 1 fails', async () => {
    const opened = openEventsDb(':memory:');
    opened.close();
    const res = await request(createApp(deps({ eventsDb: opened.reader }), baseConfig)).get(
      '/health'
    );
    expect(res.body).toMatchObject({ status: 'degraded', eventsDb: 'error' });
  });
});

describe('createApp /mcp auth', () => {
  it('rejects requests with no Authorization header', async () => {
    const res = await request(createApp(deps(), baseConfig)).post('/mcp').send({});
    expect(res.status).toBe(401);
  });

  it('rejects requests with the wrong bearer token', async () => {
    const res = await request(createApp(deps(), baseConfig))
      .post('/mcp')
      .set('Authorization', 'Bearer wrong')
      .send({});
    expect(res.status).toBe(401);
  });
});

describe('createApp /api/playbook', () => {
  it('is mounted', async () => {
    const res = await request(createApp(deps(), baseConfig)).get('/api/playbook');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ entries: [], registry: {} });
  });
});

describe('createApp /api/admin/backfill-rule-triage', () => {
  it('runs the backfill and returns its result shape', async () => {
    const res = await request(createApp(deps(), baseConfig)).post(
      '/api/admin/backfill-rule-triage'
    );
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
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
    });
  });
});

describe('createApp route precedence', () => {
  it('does not let the static/SPA fallback swallow /api or /health routes', async () => {
    const app = createApp(deps(), baseConfig);

    const health = await request(app).get('/health');
    expect(health.status).toBe(200);

    const findings = await request(app).get('/api/findings');
    expect(findings.status).toBe(200);
    expect(Array.isArray(findings.body)).toBe(true);
  });
});
