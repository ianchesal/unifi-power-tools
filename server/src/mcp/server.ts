import { createRequire } from 'node:module';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { LensDb } from '../db/lensDb.js';
import { listEntries, operatorBackedEntryIds } from '../db/playbookStore.js';
import type { AnalysisDeps } from './context.js';
import { assemblePlaybook, type PlaybookOptions, type SiteEntry } from './playbook/assemble.js';
import { registerPlaybookTools } from './playbookTools.js';
import { registerAnalysisTools } from './tools.js';

// src/mcp/server.ts and dist/mcp/server.js both sit two levels below server/.
const { version } = createRequire(import.meta.url)('../../package.json') as { version: string };

export const SERVER_INSTRUCTIONS =
  'unifi-siem-lens is a triage queue for findings its rules could not close on a UniFi network. ' +
  'Start with the `triage` prompt (in Claude Code: /mcp__unifi-siem-lens__triage), or call the ' +
  '`get_playbook` tool where prompts are not available, and follow the playbook it returns: it ' +
  'covers the run procedure, how to choose close or attention, and the guardrails the server enforces.';

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
export function createLensMcpServer(
  deps: AnalysisDeps,
  settings: Omit<PlaybookOptions, 'entries'>
): McpServer {
  const server = new McpServer(
    { name: 'unifi-siem-lens', version },
    { instructions: SERVER_INSTRUCTIONS }
  );
  registerAnalysisTools(server, deps);
  registerPlaybookTools(server, deps.lensDb);

  // Entries are read on each call, so an accepted proposal shows up at once.
  const playbookText = () =>
    assemblePlaybook({ ...settings, entries: activeSiteEntries(deps.lensDb) });

  server.registerPrompt(
    'triage',
    {
      title: 'Triage the analysis queue',
      description: 'Work the unifi-siem-lens analysis queue using the served playbook.',
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
