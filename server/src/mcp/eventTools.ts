import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  type EventStatsFilters,
  getCategories,
  getEvent,
  getEventStats,
  type ListEventsFilters,
  type SearchedEvent,
  searchEvents,
} from '../db/eventSearch.js';
import type { EventsDb } from '../db/eventsDb.js';
import { toolError, toolResult } from './tools.js';

export async function listEventsTool(db: EventsDb, params: ListEventsFilters) {
  return searchEvents(db, params);
}

export async function getEventTool(db: EventsDb, params: { id: number }): Promise<SearchedEvent> {
  const event = getEvent(db, params.id);
  if (!event) {
    throw new Error(`Event ${params.id} not found`);
  }
  return event;
}

export async function getCategoriesTool(db: EventsDb): Promise<{ categories: string[] }> {
  return { categories: getCategories(db) };
}

export async function getEventStatsTool(db: EventsDb, params: EventStatsFilters) {
  return { groups: getEventStats(db, params) };
}

export function registerEventTools(server: McpServer, db: EventsDb): void {
  server.tool(
    'list_events',
    'List stored UniFi SIEM events. Filters: since/until (ISO8601 timestamps, filtered on receipt time), category, severity_min, source_ip/dest_ip (exact match or CIDR, e.g. "10.0.30.0/24"), limit (default 100, max 500), offset. Events include source_client_name/mac and dest_client_name/mac when UniFi identifies a LAN client by name/MAC instead of IP (source_ip may then be null).',
    {
      since: z.string().optional(),
      until: z.string().optional(),
      category: z.string().optional(),
      severity_min: z.number().int().min(0).max(10).optional(),
      source_ip: z.string().optional(),
      dest_ip: z.string().optional(),
      limit: z.number().int().min(1).max(500).optional(),
      offset: z.number().int().min(0).optional(),
    },
    async (p) => {
      try {
        const result = await listEventsTool(db, {
          since: p.since,
          until: p.until,
          category: p.category,
          severityMin: p.severity_min,
          sourceIp: p.source_ip,
          destIp: p.dest_ip,
          limit: p.limit,
          offset: p.offset,
        });
        return toolResult(result);
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'get_event',
    'Get a single stored event by id, including its full raw syslog message. Events include source_client_name/mac and dest_client_name/mac when UniFi identifies a LAN client by name/MAC instead of IP (source_ip may then be null).',
    { id: z.number().int() },
    async (p) => {
      try {
        return toolResult(await getEventTool(db, p));
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'get_categories',
    'List the distinct event categories currently present in the store (e.g. "ips_alert", "firewall_block", "honeypot", "admin_action", "unknown").',
    {},
    async () => {
      try {
        return toolResult(await getCategoriesTool(db));
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'get_event_stats',
    'Get aggregate event counts grouped by category, severity, or source_ip, optionally within a time range (since/until, ISO8601).',
    {
      since: z.string().optional(),
      until: z.string().optional(),
      group_by: z.enum(['category', 'severity', 'source_ip']),
    },
    async (p) => {
      try {
        const result = await getEventStatsTool(db, {
          since: p.since,
          until: p.until,
          groupBy: p.group_by,
        });
        return toolResult(result);
      } catch (e) {
        return toolError(e);
      }
    }
  );
}
