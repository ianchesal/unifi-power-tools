import type { Express } from 'express';
import request from 'supertest';
import type { RunnerDeps } from '../src/analysis/runner.js';
import type { Config } from '../src/config.js';
import { type LensDb, openLensDb } from '../src/db/lensDb.js';
import type { AppDeps } from '../src/server.js';
import { type EventsDb, openEventsDb } from '../src/db/eventsDb.js';
import type { IUnifiClient } from '../src/unifi/client.js';

export interface EventRowFixture {
  received_at: string;
  category: string;
  signature?: string | null;
  source_ip?: string | null;
  action?: string | null;
  message?: string | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  source_client_mac?: string | null;
  source_client_name?: string | null;
}

// In-memory events DB built by the real migrations, so tests track the real schema.
export function seededEventsDb(rows: EventRowFixture[]): EventsDb {
  const { conn } = openEventsDb(':memory:').writer;
  const stmt = conn.prepare(
    `INSERT INTO events (received_at, category, signature, source_ip, action, message,
                         dest_ip, dest_port, source_client_mac, source_client_name, raw, parsed)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'raw-line', 1)`
  );
  for (const r of rows) {
    stmt.run(
      r.received_at,
      r.category,
      r.signature ?? null,
      r.source_ip ?? null,
      r.action ?? null,
      r.message ?? null,
      r.dest_ip ?? null,
      r.dest_port ?? null,
      r.source_client_mac ?? null,
      r.source_client_name ?? null
    );
  }
  return { conn };
}

export function runnerDeps(
  eventsDb: EventsDb,
  lensDb: LensDb,
  overrides: Partial<RunnerDeps> = {}
): RunnerDeps {
  return {
    eventsDb,
    lensDb,
    lanCidrs: [],
    trustedAdminNames: [],
    safeSignaturePrefixes: ['ET DROP', 'ET CINS'],
    ...overrides,
  };
}

// An IUnifiClient that answers every call with an empty result.
export const stubUnifiClient: IUnifiClient = {
  get: async () => [],
  getOne: async () => ({}) as never,
  post: async () => [],
  put: async () => [],
  delete: async () => {},
  cmd: async () => {},
  v2get: async () => [],
  v2getOne: async () => ({}) as never,
  v2post: async () => ({}) as never,
  v2put: async () => ({}) as never,
  v2delete: async () => {},
};

export const TEST_PASSWORD = 'test-password';

export const baseConfig = {
  port: 3002,
  host: '127.0.0.1',
  eventsDbPath: ':memory:',
  lensDbPath: ':memory:',
  lanCidrs: [],
  logLevel: 'error' as const,
  mcpSecret: 'test-secret',
  dashboardPassword: TEST_PASSWORD,
  trustProxy: null,
  trustedAdminNames: [],
  safeSignaturePrefixes: ['ET DROP'],
  homelabServicesPath: '/nonexistent/homelab-services.json',
  retentionDays: 90,
  syslogUdpPort: 10514,
  syslogBindAddress: '127.0.0.1',
  maxMessageBytes: 16384,
  unifi: null,
} as Config;

// Everything createApp needs, in memory: a bound listener stub and no UniFi.
export function appDeps(overrides: Partial<AppDeps> = {}): AppDeps {
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
  return {
    eventsDb,
    lensDb,
    runnerDeps,
    listener: { bound: () => true, droppedCount: () => 0 },
    unifiClient: null,
    ...overrides,
  };
}

// A supertest agent (cookie jar) signed in through the real login route.
export async function loginAgent(app: Express, password = TEST_PASSWORD) {
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ password });
  if (res.status !== 200) throw new Error(`login failed: ${res.status}`);
  return agent;
}
