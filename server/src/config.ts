import type { LogLevel } from './logger.js';

const DEFAULT_SAFE_SIGNATURE_PREFIXES = [
  'ET DROP',
  'ET CINS',
  'ET TOR',
  'ET COMPROMISED',
  'ET DSHIELD',
];

export interface Config {
  port: number;
  host: string;
  eventsDbPath: string;
  retentionDays: number;
  syslogUdpPort: number;
  syslogBindAddress: string;
  maxMessageBytes: number;
  lensDbPath: string;
  lanCidrs: string[];
  unifiMcpServerUrl: string | null;
  unifiMcpServerToken: string | null;
  logLevel: LogLevel;
  mcpSecret: string;
  trustedAdminNames: string[];
  safeSignaturePrefixes: string[];
  homelabServicesPath: string;
  // null when UniFi isn't configured (neither UNIFI_HOST nor UNIFI_API_KEY set).
  unifi: UnifiConfig | null;
}

export interface UnifiConfig {
  host: string;
  apiKey: string;
  site: string;
  verifyTls: boolean;
  timeoutMs: number;
  // Only the literal 'true' registers UniFi write tools on /mcp.
  allowWrites: boolean;
}

function loadUnifiConfig(): UnifiConfig | null {
  const host = process.env.UNIFI_HOST?.trim() ?? '';
  const apiKey = process.env.UNIFI_API_KEY?.trim() ?? '';
  if (!host && !apiKey) return null;
  if (!host || !apiKey) throw new Error('UNIFI_HOST and UNIFI_API_KEY must be set together');
  return {
    host,
    apiKey,
    site: process.env.UNIFI_SITE?.trim() || 'default',
    verifyTls: process.env.UNIFI_VERIFY_TLS === 'true',
    timeoutMs: parseIntEnv('UNIFI_REQUEST_TIMEOUT_MS', 10000),
    allowWrites: process.env.UNIFI_ALLOW_WRITES === 'true',
  };
}

function parseIntEnv(key: string, defaultValue: number): number {
  const raw = process.env[key];
  if (!raw) return defaultValue;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Environment variable ${key} must be a number, got: "${raw}"`);
  }
  return parsed;
}

function parseCommaList(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function loadConfig(): Config {
  if (!process.env.MCP_SECRET?.trim()) {
    throw new Error('Missing required environment variable: MCP_SECRET');
  }

  const validLevels: LogLevel[] = ['error', 'warn', 'info', 'debug'];
  const rawLogLevel = process.env.LOG_LEVEL ?? 'info';
  if (!validLevels.includes(rawLogLevel as LogLevel)) {
    throw new Error(`LOG_LEVEL must be one of: ${validLevels.join(', ')}, got: "${rawLogLevel}"`);
  }

  const lanCidrs = parseCommaList(process.env.LAN_CIDRS);

  return {
    port: parseIntEnv('PORT', 3002),
    host: process.env.HOST ?? '127.0.0.1',
    eventsDbPath: process.env.EVENTS_DB_PATH?.trim() || './data/events.db',
    retentionDays: parseIntEnv('RETENTION_DAYS', 90),
    syslogUdpPort: parseIntEnv('SYSLOG_UDP_PORT', 10514),
    syslogBindAddress: process.env.SYSLOG_BIND_ADDRESS?.trim() || '0.0.0.0',
    maxMessageBytes: parseIntEnv('MAX_MESSAGE_BYTES', 16384),
    lensDbPath: process.env.LENS_DB_PATH ?? './data/lens.db',
    lanCidrs,
    unifiMcpServerUrl: process.env.UNIFI_MCP_SERVER_URL?.trim() || null,
    unifiMcpServerToken: process.env.UNIFI_MCP_SERVER_TOKEN?.trim() || null,
    logLevel: rawLogLevel as LogLevel,
    mcpSecret: process.env.MCP_SECRET,
    trustedAdminNames: parseCommaList(process.env.TRUSTED_ADMIN_NAMES),
    safeSignaturePrefixes: process.env.SAFE_SIGNATURE_PREFIXES
      ? parseCommaList(process.env.SAFE_SIGNATURE_PREFIXES)
      : DEFAULT_SAFE_SIGNATURE_PREFIXES,
    homelabServicesPath: process.env.HOMELAB_SERVICES_PATH ?? './data/homelab-services.json',
    unifi: loadUnifiConfig(),
  };
}
