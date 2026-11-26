import { createRequire } from 'node:module';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { LensDb } from '../db/lensDb.js';
import { listEntries, operatorBackedEntryIds } from '../db/playbookStore.js';
import type { AnalysisDeps } from './context.js';
import { registerEventTools } from './eventTools.js';
import { assemblePlaybook, type PlaybookOptions, type SiteEntry } from './playbook/assemble.js';
import { registerPlaybookTools } from './playbookTools.js';
import { registerAnalysisTools } from './tools.js';

// src/mcp/server.ts and dist/mcp/server.js both sit two levels below server/.
const { version } = createRequire(import.meta.url)('../../package.json') as { version: string };

export const SERVER_INSTRUCTIONS =
  'unifi-power-tools serves UniFi SIEM events, the UniFi Network API and a triage queue for findings ' +
  'its rules could not close. Start with the `triage` prompt (in Claude Code: ' +
  '/mcp__unifi-power-tools__triage, if your config entry is named unifi-power-tools), or call ' +
  '`get_playbook` where prompts are not available, and follow it. Triage never calls UniFi write ' +
  'tools, even when they are present.';

function activeSiteEntries(db: LensDb): SiteEntry[] {
  const backed = operatorBackedEntryIds(db);
  return listEntries(db, { status: 'active' }).map(({ id, title, body }) => ({
    id,
    title,
    body,
    isDefault: !backed.has(id),
  }));
}

// One server per /mcp request (stateless transport), built the same way in tests.
export function createMcpServer(
  deps: AnalysisDeps,
  settings: Omit<PlaybookOptions, 'entries'>
): McpServer {
  const server = new McpServer(
    { name: 'unifi-power-tools', version },
    { instructions: SERVER_INSTRUCTIONS }
  );
  registerEventTools(server, deps.eventsDb);
  registerAnalysisTools(server, deps);
  registerPlaybookTools(server, deps.lensDb);

  // Entries are read on each call, so an accepted proposal shows up at once.
  const playbookText = () =>
    assemblePlaybook({ ...settings, entries: activeSiteEntries(deps.lensDb) });

  server.registerPrompt(
    'triage',
    {
      title: 'Triage the analysis queue',
      description: 'Work the unifi-power-tools analysis queue using the served playbook.',
    },
    () => ({
      messages: [
        {
          role: 'user' as const,
          content: { type: 'text' as const, text: playbookText() },
        },
      ],
    })
  );

  server.registerTool(
    'get_playbook',
    {
      title: 'Get the triage playbook',
      description:
        'The triage playbook: run procedure, verdict rules and guardrails. Same content as the `triage` prompt, for clients that cannot use MCP prompts. Call it first and follow it.',
    },
    () => ({ content: [{ type: 'text' as const, text: playbookText() }] })
  );

  return server;
}
