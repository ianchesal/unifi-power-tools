import { Router } from 'express';
import {
  eventsOverTime,
  listEvents,
  severityDistribution,
  topSignatures,
  topSourceIps,
} from '../db/eventQueries.js';
import type { EventsDb } from '../db/eventsDb.js';

export function createEventsRouter(db: EventsDb): Router {
  const router = Router();

  router.get('/events', (req, res) => {
    const since = typeof req.query.since === 'string' ? req.query.since : undefined;
    const limit = req.query.limit ? Number(req.query.limit) : undefined;
    res.json(listEvents(db, { since, limit }));
  });

  // Named to avoid the substring "events" — ad blockers and privacy
  // extensions (uBlock Origin, Brave Shields, etc.) commonly filter any
  // request path containing it as an analytics-tracking pattern, silently
  // cancelling the fetch client-side before it ever reaches this server.
  // That was the root cause of the Trends chart and "Events, 24h" KPI
  // appearing permanently empty for some users despite the backend and
  // data being completely healthy.
  router.get('/stats/activity-over-time', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 30;
    res.json(eventsOverTime(db, { sinceDays }));
  });

  router.get('/stats/top-signatures', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 7;
    const limit = req.query.limit ? Number(req.query.limit) : 10;
    res.json(topSignatures(db, { sinceDays, limit }));
  });

  router.get('/stats/top-source-ips', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 7;
    const limit = req.query.limit ? Number(req.query.limit) : 10;
    res.json(topSourceIps(db, { sinceDays, limit }));
  });

  router.get('/stats/severity-distribution', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 7;
    res.json(severityDistribution(db, { sinceDays }));
  });

  return router;
}
