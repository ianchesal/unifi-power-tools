import type { Server } from 'node:http';
import {
  type RunnerDeps,
  runDailyAnomalyCheck,
  runDailyRecheck,
  runHourlyChecks,
} from './analysis/runner.js';
import type { Config } from './config.js';
import { openEventsDb, purgeOldEvents } from './db/eventsDb.js';
import { openLensDb } from './db/lensDb.js';
import { loadHomelabServices } from './enrichment/homelabServices.js';
import { startSyslogListener } from './ingest/listener.js';
import type { Logger } from './logger.js';
import { PLAYBOOK_DEFAULTS } from './mcp/playbook/defaults.js';
import { seedPlaybookDefaults } from './mcp/playbook/seed.js';
import { createApp } from './server.js';
import { UnifiClient } from './unifi/client.js';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
// Requested UDP receive buffer. The kernel caps it (Linux: net.core.rmem_max).
const SYSLOG_RECV_BUFFER_BYTES = 4 * 1024 * 1024;

export interface StartHooks {
  // Called after the syslog listener is bound, before the boot-time checks.
  beforeChecks?: (state: { listenerBound: boolean }) => void;
}

export interface Running {
  httpServer: Server;
  stop(): Promise<void>;
}

// Boots the whole service. Throws (the caller exits) if the events DB can't be
// opened or the syslog port can't be bound: both are fatal by design.
export async function start(
  config: Config,
  logger: Logger,
  hooks: StartHooks = {}
): Promise<Running> {
  const events = openEventsDb(config.eventsDbPath, (m) => logger.info(m));
  const lensDb = openLensDb(config.lensDbPath);

  // A seeding failure only costs the default playbook entries, so keep booting.
  try {
    const seeded = seedPlaybookDefaults(lensDb, PLAYBOOK_DEFAULTS, new Date().toISOString());
    logger.info(
      `Playbook defaults: ${seeded.inserted} inserted, ${seeded.proposed} update(s) proposed`
    );
  } catch (err) {
    logger.error('Seeding playbook defaults failed', err);
  }

  // Bind before any analysis runs: the boot-time checks are synchronous and
  // block the event loop, and UDP sent before the bind is simply lost.
  const listener = await startSyslogListener(events.writer, {
    port: config.syslogUdpPort,
    bindAddress: config.syslogBindAddress,
    maxMessageBytes: config.maxMessageBytes,
    recvBufferSize: SYSLOG_RECV_BUFFER_BYTES,
    log: (m) => logger.warn(m),
  });
  logger.info(`Syslog UDP listener bound on ${config.syslogBindAddress}:${config.syslogUdpPort}`);

  const purgeSafely = () => {
    try {
      const deleted = purgeOldEvents(events.writer, config.retentionDays);
      if (deleted > 0)
        logger.info(`Purged ${deleted} events older than ${config.retentionDays} days`);
    } catch (err) {
      logger.error('Event retention purge failed', err);
    }
  };
  const purgeTimer = setInterval(purgeSafely, HOUR_MS);

  const homelabServices = loadHomelabServices(config.homelabServicesPath);
  const runnerDeps: RunnerDeps = {
    eventsDb: events.reader,
    lensDb,
    lanCidrs: config.lanCidrs,
    trustedAdminNames: config.trustedAdminNames,
    safeSignaturePrefixes: config.safeSignaturePrefixes,
    homelabServices,
  };

  const runChecksSafely = () => {
    try {
      const hourly = runHourlyChecks(runnerDeps);
      logger.info(`Hourly analysis checks touched ${hourly.findingsTouched} finding(s)`);
    } catch (err) {
      logger.error('Hourly analysis checks failed', err);
    }
  };

  // Anomaly check first, so a finding it creates is routed before the recheck
  // runs; each step in its own try/catch so one failing can't skip the other.
  const runDailyCheckSafely = () => {
    try {
      const daily = runDailyAnomalyCheck(runnerDeps);
      logger.info(`Daily anomaly check touched ${daily.findingsTouched} finding(s)`);
    } catch (err) {
      logger.error('Daily anomaly check failed', err);
    }
    try {
      const recheck = runDailyRecheck(runnerDeps);
      logger.info(
        `Daily recheck: ${recheck.checked} checked, ${recheck.requeued} requeued, ${recheck.stillClosed} still closed`
      );
    } catch (err) {
      logger.error('Daily recheck failed', err);
    }
  };

  hooks.beforeChecks?.({ listenerBound: listener.bound() });
  runChecksSafely();
  const hourlyTimer = setInterval(runChecksSafely, HOUR_MS);
  runDailyCheckSafely();
  const dailyTimer = setInterval(runDailyCheckSafely, DAY_MS);

  const unifiClient = config.unifi
    ? new UnifiClient({
        host: config.unifi.host,
        apiKey: config.unifi.apiKey,
        site: config.unifi.site,
        verifyTls: config.unifi.verifyTls,
        timeoutMs: config.unifi.timeoutMs,
      })
    : null;
  logger.info(
    config.unifi
      ? `UniFi: ${config.unifi.host} site ${config.unifi.site}, write tools ${config.unifi.allowWrites ? 'ENABLED' : 'off'}`
      : 'UniFi: not configured (no UniFi tools, no enrichment)'
  );

  const app = createApp(
    { eventsDb: events.reader, lensDb, runnerDeps, listener, unifiClient },
    config
  );
  const httpServer = await new Promise<Server>((resolve) => {
    const s = app.listen(config.port, config.host, () => resolve(s));
  });
  logger.info(`Listening on ${config.host}:${config.port}`);

  return {
    httpServer,
    stop: async () => {
      clearInterval(purgeTimer);
      clearInterval(hourlyTimer);
      clearInterval(dailyTimer);
      await listener.close();
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      lensDb.close();
      events.close();
    },
  };
}
