import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  const savedEnv = { ...process.env };

  beforeEach(() => {
    process.env.MCP_SECRET = 'test-secret';
    process.env.DASHBOARD_PASSWORD = 'dash-password';
    delete process.env.TRUST_PROXY;
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

  it('throws when DASHBOARD_PASSWORD is missing', () => {
    delete process.env.DASHBOARD_PASSWORD;
    expect(() => loadConfig()).toThrow(/DASHBOARD_PASSWORD/);
  });

  it('throws when DASHBOARD_PASSWORD equals MCP_SECRET', () => {
    process.env.DASHBOARD_PASSWORD = 'test-secret';
    expect(() => loadConfig()).toThrow(/DASHBOARD_PASSWORD must differ from MCP_SECRET/);
  });

  it('reads DASHBOARD_PASSWORD', () => {
    expect(loadConfig().dashboardPassword).toBe('dash-password');
  });

  it('defaults TRUST_PROXY to null and passes other values through', () => {
    expect(loadConfig().trustProxy).toBeNull();
    process.env.TRUST_PROXY = '172.18.0.2';
    expect(loadConfig().trustProxy).toBe('172.18.0.2');
  });

  it.each(['true', 'TRUE', 'True'])('rejects TRUST_PROXY=%s', (v) => {
    process.env.TRUST_PROXY = v;
    expect(() => loadConfig()).toThrow(/TRUST_PROXY/);
  });

  describe('UniFi', () => {
    beforeEach(() => {
      for (const k of ['UNIFI_HOST', 'UNIFI_API_KEY', 'UNIFI_SITE', 'UNIFI_VERIFY_TLS', 'UNIFI_REQUEST_TIMEOUT_MS', 'UNIFI_ALLOW_WRITES']) {
        delete process.env[k];
      }
    });

    it('is null when neither UNIFI_HOST nor UNIFI_API_KEY is set', () => {
      expect(loadConfig().unifi).toBeNull();
    });

    it('throws when only one of UNIFI_HOST / UNIFI_API_KEY is set', () => {
      process.env.UNIFI_HOST = 'https://unifi.example';
      expect(() => loadConfig()).toThrow('UNIFI_HOST and UNIFI_API_KEY must be set together');
      delete process.env.UNIFI_HOST;
      process.env.UNIFI_API_KEY = 'key';
      expect(() => loadConfig()).toThrow('UNIFI_HOST and UNIFI_API_KEY must be set together');
    });

    it('applies defaults when both are set, writes off', () => {
      process.env.UNIFI_HOST = 'https://unifi.example';
      process.env.UNIFI_API_KEY = 'key';
      expect(loadConfig().unifi).toEqual({
        host: 'https://unifi.example',
        apiKey: 'key',
        site: 'default',
        verifyTls: false,
        timeoutMs: 10000,
        allowWrites: false,
      });
    });

    it('enables writes only for the literal "true"', () => {
      process.env.UNIFI_HOST = 'https://unifi.example';
      process.env.UNIFI_API_KEY = 'key';
      process.env.UNIFI_ALLOW_WRITES = 'TRUE';
      expect(loadConfig().unifi?.allowWrites).toBe(false);
      process.env.UNIFI_ALLOW_WRITES = '1';
      expect(loadConfig().unifi?.allowWrites).toBe(false);
      process.env.UNIFI_ALLOW_WRITES = 'true';
      expect(loadConfig().unifi?.allowWrites).toBe(true);
    });
  });
});

