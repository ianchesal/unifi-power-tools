import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  const savedEnv = { ...process.env };

  beforeEach(() => {
    process.env.MCP_SECRET = 'test-secret';
  });

  afterEach(() => {
    process.env = { ...savedEnv };
  });

  it('applies defaults', () => {
    delete process.env.LAN_CIDRS;
    delete process.env.PORT;
    const config = loadConfig();
    expect(config.port).toBe(3002);
    expect(config.host).toBe('127.0.0.1');
    expect(config.lanCidrs).toEqual([]);
    expect(config.unifiMcpServerUrl).toBeNull();
    expect(config.unifiMcpServerToken).toBeNull();
  });

  it('parses UNIFI_MCP_SERVER_TOKEN when set', () => {
    process.env.UNIFI_MCP_SERVER_TOKEN = 'secret-token';
    const config = loadConfig();
    expect(config.unifiMcpServerToken).toBe('secret-token');
  });

  it('parses LAN_CIDRS as a comma-separated list', () => {
    process.env.LAN_CIDRS = '10.0.0.0/8, 192.168.1.0/24';
    const config = loadConfig();
    expect(config.lanCidrs).toEqual(['10.0.0.0/8', '192.168.1.0/24']);
  });

  it('applies events DB and syslog defaults', () => {
    for (const k of ['EVENTS_DB_PATH', 'RETENTION_DAYS', 'SYSLOG_UDP_PORT', 'SYSLOG_BIND_ADDRESS', 'MAX_MESSAGE_BYTES']) {
      delete process.env[k];
    }
    const config = loadConfig();
    expect(config.eventsDbPath).toBe('./data/events.db');
    expect(config.retentionDays).toBe(90);
    expect(config.syslogUdpPort).toBe(10514);
    expect(config.syslogBindAddress).toBe('0.0.0.0');
    expect(config.maxMessageBytes).toBe(16384);
  });

  it('reads EVENTS_DB_PATH and the syslog settings', () => {
    process.env.EVENTS_DB_PATH = '/data/events.db';
    process.env.RETENTION_DAYS = '30';
    process.env.SYSLOG_UDP_PORT = '5514';
    const config = loadConfig();
    expect(config.eventsDbPath).toBe('/data/events.db');
    expect(config.retentionDays).toBe(30);
    expect(config.syslogUdpPort).toBe(5514);
  });

  it('throws when MCP_SECRET is missing', () => {
    delete process.env.MCP_SECRET;
    expect(() => loadConfig()).toThrow(/MCP_SECRET/);
  });

  it('defaults trustedAdminNames to empty and safeSignaturePrefixes to the built-in list', () => {
    delete process.env.TRUSTED_ADMIN_NAMES;
    delete process.env.SAFE_SIGNATURE_PREFIXES;
    const config = loadConfig();
    expect(config.trustedAdminNames).toEqual([]);
    expect(config.safeSignaturePrefixes).toEqual([
      'ET DROP',
      'ET CINS',
      'ET TOR',
      'ET COMPROMISED',
      'ET DSHIELD',
    ]);
  });

  it('parses TRUSTED_ADMIN_NAMES and SAFE_SIGNATURE_PREFIXES as comma-separated lists', () => {
    process.env.TRUSTED_ADMIN_NAMES = 'Ian C., Jane Doe';
    process.env.SAFE_SIGNATURE_PREFIXES = 'ET DROP, ET CUSTOM';
    const config = loadConfig();
    expect(config.trustedAdminNames).toEqual(['Ian C.', 'Jane Doe']);
    expect(config.safeSignaturePrefixes).toEqual(['ET DROP', 'ET CUSTOM']);
  });
});
