import dgram from 'node:dgram';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Config } from '../src/config.js';
import { createLogger } from '../src/logger.js';
import { start } from '../src/start.js';

const SYSLOG_PORT = 31614;
let dir: string;

function config(): Config {
  return {
    port: 0,
    host: '127.0.0.1',
    eventsDbPath: join(dir, 'events.db'),
    lensDbPath: join(dir, 'lens.db'),
    retentionDays: 90,
    syslogUdpPort: SYSLOG_PORT,
    syslogBindAddress: '127.0.0.1',
    maxMessageBytes: 16384,
    lanCidrs: [],
    unifiMcpServerUrl: null,
    unifiMcpServerToken: null,
    logLevel: 'error',
    mcpSecret: 'test-secret',
    trustedAdminNames: [],
    safeSignaturePrefixes: ['ET DROP'],
    homelabServicesPath: join(dir, 'homelab-services.json'),
    unifi: null,
  };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'upt-start-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('start', () => {
  it('binds the syslog listener before the boot-time analysis checks run', async () => {
    let boundAtChecks: boolean | null = null;
    const running = await start(config(), createLogger('error'), {
      beforeChecks: ({ listenerBound }) => {
        boundAtChecks = listenerBound;
      },
    });
    await running.stop();
    expect(boundAtChecks).toBe(true);
  });

  it('serves /health once started', async () => {
    const running = await start(config(), createLogger('error'));
    try {
      const address = running.httpServer.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      expect(await res.json()).toMatchObject({ status: 'ok', eventsDb: 'ok' });
    } finally {
      await running.stop();
    }
  });

  it('rejects when the syslog port is already in use', async () => {
    const squatter = dgram.createSocket('udp4');
    await new Promise<void>((resolve) => squatter.bind(SYSLOG_PORT, '127.0.0.1', resolve));
    try {
      await expect(start(config(), createLogger('error'))).rejects.toThrow();
    } finally {
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
    }
  });
});
