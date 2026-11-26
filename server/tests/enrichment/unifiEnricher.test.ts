import { describe, expect, it } from 'vitest';
import { createUnifiEnricher, FIREWALL_SUMMARY_MAX_BYTES } from '../../src/enrichment/unifiEnricher.js';
import type { IUnifiClient } from '../../src/unifi/client.js';
import { stubUnifiClient } from '../helpers.js';

function clientReturning(byPath: Record<string, unknown[]>, calls: string[] = []): IUnifiClient {
  return {
    ...stubUnifiClient,
    get: async <T>(path: string) => {
      calls.push(path);
      return (byPath[path] ?? []) as T[];
    },
  };
}

const failing: IUnifiClient = {
  ...stubUnifiClient,
  get: async () => {
    throw new Error('ECONNREFUSED');
  },
};

describe('createUnifiEnricher.resolveClient', () => {
  it('matches on ip', async () => {
    const e = createUnifiEnricher(
      clientReturning({ 'stat/alluser': [{ ip: '192.0.2.10', name: 'nas', network: 'LAN' }] })
    );
    expect(await e.resolveClient('192.0.2.10')).toEqual({ name: 'nas', network: 'LAN' });
  });

  it('matches an offline client on last_ip', async () => {
    const e = createUnifiEnricher(
      clientReturning({ 'stat/alluser': [{ last_ip: '192.0.2.11', name: 'laptop', network: 'IoT' }] })
    );
    expect(await e.resolveClient('192.0.2.11')).toEqual({ name: 'laptop', network: 'IoT' });
  });

  it('falls back to hostname when there is no name', async () => {
    const e = createUnifiEnricher(
      clientReturning({ 'stat/alluser': [{ ip: '192.0.2.12', hostname: 'printer', network: 'LAN' }] })
    );
    expect(await e.resolveClient('192.0.2.12')).toEqual({ name: 'printer', network: 'LAN' });
  });

  it('defaults network to unknown', async () => {
    const e = createUnifiEnricher(clientReturning({ 'stat/alluser': [{ ip: '192.0.2.13', name: 'tv' }] }));
    expect(await e.resolveClient('192.0.2.13')).toEqual({ name: 'tv', network: 'unknown' });
  });

  it('returns null when nothing matches', async () => {
    const e = createUnifiEnricher(clientReturning({ 'stat/alluser': [{ ip: '192.0.2.14', name: 'x' }] }));
    expect(await e.resolveClient('192.0.2.99')).toBeNull();
  });

  it('returns null when the match has neither name nor hostname', async () => {
    const e = createUnifiEnricher(clientReturning({ 'stat/alluser': [{ ip: '192.0.2.15', mac: 'aa' }] }));
    expect(await e.resolveClient('192.0.2.15')).toBeNull();
  });

  it('returns null on an API error instead of throwing', async () => {
    expect(await createUnifiEnricher(failing).resolveClient('192.0.2.10')).toBeNull();
  });

  it('asks stat/alluser (online and offline), not stat/sta', async () => {
    const calls: string[] = [];
    await createUnifiEnricher(clientReturning({}, calls)).resolveClient('192.0.2.10');
    expect(calls).toEqual(['stat/alluser']);
  });
});

describe('createUnifiEnricher.getFirewallSummary', () => {
  it('returns the firewall rules as JSON text', async () => {
    const e = createUnifiEnricher(
      clientReturning({ 'rest/firewallrule': [{ _id: 'r1', name: 'drop bad', ruleset: 'WAN_IN' }] })
    );
    const text = await e.getFirewallSummary();
    expect(JSON.parse(text ?? '')).toMatchObject({ total: 1, data: [{ _id: 'r1' }] });
  });

  it(`caps the summary at ${FIREWALL_SUMMARY_MAX_BYTES} bytes with a marker`, async () => {
    const rules = Array.from({ length: 100 }, (_, i) => ({ _id: `r${i}`, name: 'x'.repeat(200) }));
    const text = (await createUnifiEnricher(clientReturning({ 'rest/firewallrule': rules })).getFirewallSummary()) ?? '';
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(FIREWALL_SUMMARY_MAX_BYTES + 32);
    expect(text.endsWith('\n…[truncated]')).toBe(true);
  });

  it('returns null on an API error', async () => {
    expect(await createUnifiEnricher(failing).getFirewallSummary()).toBeNull();
  });
});

describe('createUnifiEnricher(null)', () => {
  it('resolves null for both methods without a client', async () => {
    const e = createUnifiEnricher(null);
    expect(await e.resolveClient('192.0.2.10')).toBeNull();
    expect(await e.getFirewallSummary()).toBeNull();
  });
});
