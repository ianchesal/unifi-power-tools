import { createRequire } from 'node:module';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AnalysisDeps } from './context.js';
import { assemblePlaybook } from './playbook/assemble.js';
import { registerAnalysisTools } from './tools.js';

// src/mcp/server.ts and dist/mcp/server.js both sit two levels below server/.
const { version } = createRequire(import.meta.url)('../../package.json') as { version: string };

export const SERVER_INSTRUCTIONS =
  'unifi-siem-lens is a triage queue for findings its rules could not close on a UniFi network. ' +
  'Start with the `triage` prompt (in Claude Code: /mcp__unifi-siem-lens__triage), or call the ' +
  '`get_playbook` tool where prompts are not available, and follow the playbook it returns: it ' +
  'covers the run procedure, how to choose close or attention, and the guardrails the server enforces.';

// One server per /mcp request (stateless transport), built the same way in tests.
export function createLensMcpServer(deps: AnalysisDeps): McpServer {
  const server = new McpServer(
    { name: 'unifi-siem-lens', version },
    { instructions: SERVER_INSTRUCTIONS }
  );
  registerAnalysisTools(server, deps);

  server.registerPrompt(
    'triage',
    {
      title: 'Triage the analysis queue',
      description: 'Work the unifi-siem-lens analysis queue using the served playbook.',
    },
    () => ({
      messages: [
        { role: 'user' as const, content: { type: 'text' as const, text: assemblePlaybook() } },
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
    () => ({ content: [{ type: 'text' as const, text: assemblePlaybook() }] })
  );

  return server;
}
