import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, { type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { type RunnerDeps, runHourlyChecks, runRuleTriageBackfill } from './analysis/runner.js';
import { createAnalysisRequestsRouter } from './api/analysisRequests.js';
import { createEventsRouter } from './api/events.js';
import { createFindingsRouter } from './api/findings.js';
import { createPlaybookRouter } from './api/playbook.js';
import { secretEquals } from './auth/secretCompare.js';
import type { Config } from './config.js';
import type { EventsDb } from './db/eventsDb.js';
import type { LensDb } from './db/lensDb.js';
import { loadHomelabServices } from './enrichment/homelabServices.js';
import { createUnifiMcpClient } from './enrichment/unifiMcpClient.js';
import type { SyslogListener } from './ingest/listener.js';
import { createMcpServer } from './mcp/server.js';
import type { IUnifiClient } from './unifi/client.js';

export interface AppDeps {
  eventsDb: EventsDb;
  lensDb: LensDb;
  runnerDeps: RunnerDeps;
  listener: Pick<SyslogListener, 'bound' | 'droppedCount'>;
  unifiClient: IUnifiClient | null;
}

export function createApp(deps: AppDeps, config: Config) {
  const { eventsDb, lensDb, runnerDeps, listener, unifiClient } = deps;
  const app = express();
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 300,
      standardHeaders: true,
      legacyHeaders: false,
    })
  );
  app.use(express.json());

  const unifiMcp = createUnifiMcpClient(config.unifiMcpServerUrl, config.unifiMcpServerToken);
  const homelabServices = loadHomelabServices(config.homelabServicesPath);

  const mcpAuthMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const match = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
    if (!match || !secretEquals(match[1], config.mcpSecret)) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  };

  // Liveness: no network calls. status is ok only if syslog is bound and the
  // events DB answers.
  const coreStatus = () => {
    let eventsDbStatus: 'ok' | 'error' = 'ok';
    try {
      eventsDb.conn.prepare('SELECT 1').get();
    } catch {
      eventsDbStatus = 'error';
    }
    const bound = listener.bound();
    return {
      status: bound && eventsDbStatus === 'ok' ? ('ok' as const) : ('degraded' as const),
      syslog: { bound, droppedMessages: listener.droppedCount() },
      eventsDb: eventsDbStatus,
    };
  };

  app.get('/health', (_req, res) => {
    res.json(coreStatus());
  });

  // Readiness: adds UniFi reachability. UniFi being down doesn't make the
  // service unready for ingest, so only the core status decides the code.
  app.get('/ready', async (_req, res) => {
    const core = coreStatus();
    let unifi: 'ok' | 'unavailable' | 'not_configured' = 'not_configured';
    if (unifiClient) {
      try {
        await unifiClient.get('stat/sysinfo');
        unifi = 'ok';
      } catch {
        unifi = 'unavailable';
      }
    }
    res.status(core.status === 'ok' ? 200 : 503).json({ ...core, unifi });
  });

  app.use('/api', createEventsRouter(eventsDb));
  app.use('/api', createFindingsRouter(lensDb, eventsDb));
  app.use('/api', createAnalysisRequestsRouter(lensDb));
  app.use('/api/playbook', createPlaybookRouter(lensDb, homelabServices));

  app.post('/api/analysis/run', (_req, res) => {
    const result = runHourlyChecks(runnerDeps);
    res.json(result);
  });

  app.post('/api/admin/backfill-rule-triage', (_req, res) => {
    const result = runRuleTriageBackfill(runnerDeps);
    res.json(result);
  });

  app.post('/mcp', mcpAuthMiddleware, async (req, res, next) => {
    const mcpServer = createMcpServer(
      {
        lensDb,
        eventsDb,
        unifiMcp,
        homelabServices,
        unifi: unifiClient
          ? { client: unifiClient, allowWrites: config.unifi?.allowWrites === true }
          : null,
      },
      { trustedAdminNames: config.trustedAdminNames }
    );
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      transport.close();
      mcpServer.close();
    });
    try {
      await mcpServer.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      next(err);
    }
  });

  // Production: serve web's built static output (web/dist) as a single process.
  // Resolved relative to this module's *built* location (server/dist/server.js),
  // not its source location, so it works when running the compiled dist/index.js:
  // server/dist/server.js -> ../../web/dist -> web/dist.
  // Mounted AFTER all /api, /mcp, and /health routes above so it can never shadow
  // them. If web/dist doesn't exist (e.g. server-only development), no-op rather
  // than crash the server at boot.
  const webDistDir = join(fileURLToPath(new URL('.', import.meta.url)), '../../web/dist');
  if (existsSync(webDistDir)) {
    app.use(express.static(webDistDir));
    // Express 5 (path-to-regexp v6+) no longer accepts a bare '*' route pattern,
    // so use a path-less middleware instead — it matches every method/path.
    app.use((req, res, next) => {
      if (
        req.method !== 'GET' ||
        req.path.startsWith('/api') ||
        req.path.startsWith('/mcp') ||
        req.path.startsWith('/health') ||
        req.path.startsWith('/ready')
      ) {
        next();
        return;
      }
      res.sendFile(join(webDistDir, 'index.html'));
    });
  }

  return app;
}
