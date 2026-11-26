import { loadConfig } from './config.js';
import { createLogger } from './logger.js';
import { start } from './start.js';

const config = loadConfig();
const logger = createLogger(config.logLevel);

// An async /mcp or UniFi path that rejects without a handler must not take
// syslog ingest down with it: log and keep running.
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled promise rejection', reason);
});

logger.info('Starting unifi-power-tools');

let running: Awaited<ReturnType<typeof start>>;
try {
  running = await start(config, logger);
} catch (err) {
  logger.error('Startup failed', err);
  process.exit(1);
}

async function shutdown(signal: string): Promise<void> {
  logger.info(`Received ${signal}, shutting down`);
  await running.stop();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
