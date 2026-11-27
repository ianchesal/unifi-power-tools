import { scryptSync } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  getOrCreateSessionSecret,
  issueToken,
  SESSION_KEY_SCRYPT,
  SESSION_TTL_MS,
  sessionKey,
  verifyToken,
} from '../../src/auth/session.js';
import { openLensDb } from '../../src/db/lensDb.js';

const NOW = new Date('2026-11-26T12:00:00.000Z');
const secret = Buffer.alloc(32, 7);
const key = sessionKey(secret, 'hunter2');

describe('sessionKey', () => {
  it('is derived with scrypt, so lens.db plus a cookie can\'t be brute-forced at hash speed', () => {
    expect(key.equals(scryptSync('hunter2', secret, 32, SESSION_KEY_SCRYPT))).toBe(true);
  });
});

describe('issueToken / verifyToken', () => {
  it('round-trips a fresh token', () => {
    expect(verifyToken(key, issueToken(key, NOW), NOW)).toBe(true);
  });

  it('expires after SESSION_TTL_MS', () => {
    const token = issueToken(key, NOW);
    expect(verifyToken(key, token, new Date(NOW.getTime() + SESSION_TTL_MS - 1))).toBe(true);
    expect(verifyToken(key, token, new Date(NOW.getTime() + SESSION_TTL_MS + 1))).toBe(false);
  });

  it('rejects a tampered MAC', () => {
    const token = issueToken(key, NOW);
    const [expiry, mac] = token.split('.');
    const flipped = (mac[0] === 'A' ? 'B' : 'A') + mac.slice(1);
    expect(verifyToken(key, `${expiry}.${flipped}`, NOW)).toBe(false);
  });

  it('rejects a tampered expiry', () => {
    const [expiry, mac] = issueToken(key, NOW).split('.');
    expect(verifyToken(key, `${Number(expiry) + 1000}.${mac}`, NOW)).toBe(false);
  });

  it.each(['', 'abc', '1.2.3', '.', 'notanumber.abc'])('rejects malformed %j', (t) => {
    expect(verifyToken(key, t, NOW)).toBe(false);
  });

  it('a key from a different password rejects the token (password change logs out)', () => {
    const token = issueToken(key, NOW);
    expect(verifyToken(sessionKey(secret, 'new-password'), token, NOW)).toBe(false);
  });

  it('a key from a different secret rejects the token', () => {
    const token = issueToken(key, NOW);
    expect(verifyToken(sessionKey(Buffer.alloc(32, 9), 'hunter2'), token, NOW)).toBe(false);
  });
});

describe('getOrCreateSessionSecret', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'upt-session-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('creates 32 random bytes once and returns the same bytes again', () => {
    const db = openLensDb(':memory:');
    const first = getOrCreateSessionSecret(db);
    expect(first).toHaveLength(32);
    expect(getOrCreateSessionSecret(db).equals(first)).toBe(true);
  });

  it('survives reopening the same file DB', () => {
    const path = join(dir, 'lens.db');
    const db = openLensDb(path);
    const first = getOrCreateSessionSecret(db);
    db.close();
    const reopened = openLensDb(path);
    expect(getOrCreateSessionSecret(reopened).equals(first)).toBe(true);
    reopened.close();
  });

  it('differs between installs', () => {
    expect(
      getOrCreateSessionSecret(openLensDb(':memory:')).equals(
        getOrCreateSessionSecret(openLensDb(':memory:'))
      )
    ).toBe(false);
  });
});
