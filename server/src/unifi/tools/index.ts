import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ZodRawShape } from 'zod';
import type { IUnifiClient } from '../client.js';
import { CLIENT_TOOLS_READ_ONLY, registerClientTools } from './clients.js';
import { FIREWALL_TOOLS_READ_ONLY, registerFirewallTools } from './firewall.js';
import { MONITORING_TOOLS_READ_ONLY, registerMonitoringTools } from './monitoring.js';
import { NETWORK_TOOLS_READ_ONLY, registerNetworkTools } from './network.js';
import { POLICY_TOOLS_READ_ONLY, registerPolicyTools } from './policies.js';
import { PORT_TOOLS_READ_ONLY, registerPortTools } from './ports.js';
import { registerSecurityTools, SECURITY_TOOLS_READ_ONLY } from './security.js';
import { registerTrafficTools, TRAFFIC_TOOLS_READ_ONLY } from './traffic.js';
import type { ToolResult, ToolSink } from './util.js';

export interface UnifiToolDef {
  name: string;
  description: string;
  inputSchema: ZodRawShape;
  readOnly: boolean;
  // biome-ignore lint/suspicious/noExplicitAny: args are typed by inputSchema
  handler: (args: any) => Promise<ToolResult>;
}

const MODULES: [(sink: ToolSink, client: IUnifiClient) => void, Record<string, boolean>][] = [
  [registerFirewallTools, FIREWALL_TOOLS_READ_ONLY],
  [registerPolicyTools, POLICY_TOOLS_READ_ONLY],
  [registerNetworkTools, NETWORK_TOOLS_READ_ONLY],
  [registerClientTools, CLIENT_TOOLS_READ_ONLY],
  [registerTrafficTools, TRAFFIC_TOOLS_READ_ONLY],
  [registerPortTools, PORT_TOOLS_READ_ONLY],
  [registerMonitoringTools, MONITORING_TOOLS_READ_ONLY],
  [registerSecurityTools, SECURITY_TOOLS_READ_ONLY],
];

// Every UniFi tool with its hand-declared readOnly flag. Throws if a module
// registers a tool its READ_ONLY map doesn't declare.
export function allUnifiTools(client: IUnifiClient): UnifiToolDef[] {
  const tools: UnifiToolDef[] = [];
  for (const [register, readOnlyMap] of MODULES) {
    register(
      {
        tool: (name, description, inputSchema, handler) => {
          const readOnly = readOnlyMap[name];
          if (typeof readOnly !== 'boolean') {
            throw new Error(`UniFi tool ${name} has no readOnly declaration`);
          }
          tools.push({ name, description, inputSchema, readOnly, handler });
        },
      },
      client
    );
  }
  return tools;
}

// Write tools are not registered at all unless allowWrites: a session never
// sees them, rather than seeing them and being refused.
export function registerUnifiTools(
  server: McpServer,
  tools: UnifiToolDef[],
  opts: { allowWrites: boolean }
): void {
  for (const t of tools) {
    if (!t.readOnly && !opts.allowWrites) continue;
    server.registerTool(
      t.name,
      {
        description: t.description,
        inputSchema: t.inputSchema,
        annotations: { readOnlyHint: t.readOnly, destructiveHint: !t.readOnly },
      },
      t.handler
    );
  }
}
