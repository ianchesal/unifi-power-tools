import {
  type RunnerDeps,
  runDailyAnomalyCheck,
  runDailyRecheck,
  runHourlyChecks,
} from './analysis/runner.js';
import { loadConfig } from './config.js';
import { openLensDb } from './db/lensDb.js';
import { openSinkDb, type SinkDb, verifySchema } from './db/sinkDb.js';
import { loadHomelabServices } from './enrichment/homelabServices.js';
import { createLogger } from './logger.js';
import { PLAYBOOK_DEFAULTS } from './mcp/playbook/defaults.js';
import { seedPlaybookDefaults } from './mcp/playbook/seed.js';
import { createApp, type SchemaCheckResult } from './server.js';

const config = loadConfig();
const logger = createLogger(config.logLevel);

logger.info('Starting unifi-siem-lens');

// openSinkDb throws a raw native error if SINK_DB_PATH points to a file that
// doesn't exist (or isn't readable). That shouldn't take the whole process
// down: boot degraded instead, so /health and the rest of the API still come
// up and can report the problem, and retry is just a restart away once the
// sink DB shows up.
let sinkDb: SinkDb | null = null;
let schemaCheck: SchemaCheckResult | null = null;
try {
  sinkDb = openSinkDb(config.sinkDbPath);
  schemaCheck = verifySchema(sinkDb);
  if (!schemaCheck.ok) {
    logger.error(
      `Sink DB schema mismatch, missing columns: ${schemaCheck.missingColumns.join(', ')}`
    );
  }
} catch (err) {
  logger.error(`Failed to open sink DB at ${config.sinkDbPath}; starting in degraded mode`, err);
  sinkDb = null;
}

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
const homelabServices = loadHomelabServices(config.homelabServicesPath);
const runnerDeps: RunnerDeps | null = sinkDb
  ? {
      sinkDb,
      lensDb,
      lanCidrs: config.lanCidrs,
      trustedAdminNames: config.trustedAdminNames,
      safeSignaturePrefixes: config.safeSignaturePrefixes,
      homelabServices,
    }
  : null;

function runChecksSafely(): void {
  if (!runnerDeps) {
    logger.warn('Skipping hourly analysis checks: sink DB unavailable');
    return;
  }
  try {
    const hourly = runHourlyChecks(runnerDeps);
    logger.info(`Hourly analysis checks touched ${hourly.findingsTouched} finding(s)`);
  } catch (err) {
    logger.error('Hourly analysis checks failed', err);
  }
}

runChecksSafely();
const hourlyTimer = setInterval(runChecksSafely, 60 * 60 * 1000);

// Anomaly check first, so a finding it creates is routed before the recheck
// runs; each step in its own try/catch so one failing can't skip the other.
function runDailyCheckSafely(): void {
  if (!runnerDeps) {
    logger.warn('Skipping daily anomaly check and recheck: sink DB unavailable');
    return;
  }
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
}

runDailyCheckSafely();
const dailyTimer = setInterval(runDailyCheckSafely, 24 * 60 * 60 * 1000);

const app = createApp(sinkDb, lensDb, runnerDeps, config, schemaCheck);
const httpServer = app.listen(config.port, config.host, () => {
  logger.info(`Listening on ${config.host}:${config.port}`);
  logger.info(`GET http://${config.host}:${config.port}/health`);
});

async function shutdown(signal: string): Promise<void> {
  logger.info(`Received ${signal}, shutting down`);
  clearInterval(hourlyTimer);
  clearInterval(dailyTimer);
  httpServer.close();
  lensDb.close();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
