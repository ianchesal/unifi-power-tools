import type { IUnifiClient } from '../unifi/client.js';
import { listFirewallRules } from '../unifi/tools/firewall.js';

// Optional UniFi context for an analysis bundle. Never throws and never blocks
// the bundle: no client configured, no match or any API error all give null.
export interface UnifiEnricher {
  resolveClient(ip: string): Promise<{ name: string; network: string } | null>;
  getFirewallSummary(): Promise<string | null>;
}

// The summary goes into an LLM context bundle, so keep it bounded.
export const FIREWALL_SUMMARY_MAX_BYTES = 8192;
const TRUNCATED_MARKER = '\n…[truncated]';

function str(v: unknown): string | null {
  return typeof v === 'string' && v.trim() ? v : null;
}

function capBytes(text: string, max: number): string {
  const buf = Buffer.from(text, 'utf8');
  if (buf.byteLength <= max) return text;
  // Cutting mid-character leaves a replacement char at worst; fine for context text.
  return buf.subarray(0, max).toString('utf8') + TRUNCATED_MARKER;
}

async function orNull<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn();
  } catch {
    return null;
  }
}

export function createUnifiEnricher(client: IUnifiClient | null): UnifiEnricher {
  if (!client) {
    return { resolveClient: async () => null, getFirewallSummary: async () => null };
  }
  return {
    resolveClient: (ip) =>
      orNull(async () => {
        // stat/alluser covers offline clients too; they carry only last_ip.
        const clients = await client.get<Record<string, unknown>>('stat/alluser');
        const match = clients.find((c) => c.ip === ip || c.last_ip === ip);
        if (!match) return null;
        const name = str(match.name) ?? str(match.hostname);
        if (!name) return null;
        return { name, network: str(match.network) ?? 'unknown' };
      }),
    getFirewallSummary: () =>
      orNull(async () =>
        capBytes(JSON.stringify(await listFirewallRules(client, {})), FIREWALL_SUMMARY_MAX_BYTES)
      ),
  };
}
