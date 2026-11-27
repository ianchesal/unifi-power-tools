import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { LensDb } from '../db/lensDb.js';

// Dashboard sessions: a stateless signed cookie, `<expiryMs>.<base64url HMAC>`.
//
// The HMAC key is scrypt(password, sessionSecret). sessionSecret is 32 random
// bytes made on first boot and kept in lens.db, so:
// - sessions survive restarts (same secret, same password -> same key);
// - changing DASHBOARD_PASSWORD logs everyone out (new key);
// - a captured cookie can't be used to guess the password offline, because
//   the key isn't derivable from the password alone, and even with lens.db
//   each guess costs an scrypt.

export const SESSION_COOKIE = 'upt_session';
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const SECRET_META_KEY = 'session_secret';

export function getOrCreateSessionSecret(db: LensDb): Buffer {
  const row = db.conn.prepare('SELECT value FROM meta WHERE key = ?').get(SECRET_META_KEY) as
    | { value: string }
    | undefined;
  if (row) return Buffer.from(row.value, 'hex');
  const secret = randomBytes(32);
  // OR IGNORE + re-read: if two openers race, both end up with the stored one.
  db.conn
    .prepare('INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)')
    .run(SECRET_META_KEY, secret.toString('hex'));
  const stored = db.conn.prepare('SELECT value FROM meta WHERE key = ?').get(SECRET_META_KEY) as {
    value: string;
  };
  return Buffer.from(stored.value, 'hex');
}

// scrypt (Node's default cost, N=2^14): computed once per process start, and
// slow enough that someone holding lens.db and a cookie can't test password
// guesses at hash speed.
export const SESSION_KEY_SCRYPT = { N: 16384, r: 8, p: 1 } as const;

export function sessionKey(secret: Buffer, password: string): Buffer {
  return scryptSync(password, secret, 32, SESSION_KEY_SCRYPT);
}

function mac(key: Buffer, expiryMs: string): Buffer {
  return createHmac('sha256', key).update(expiryMs).digest();
}

export function issueToken(key: Buffer, now: Date): string {
  const expiryMs = String(now.getTime() + SESSION_TTL_MS);
  return `${expiryMs}.${mac(key, expiryMs).toString('base64url')}`;
}

export function verifyToken(key: Buffer, token: string, now: Date): boolean {
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [expiryMs, given] = parts;
  if (!/^\d+$/.test(expiryMs)) return false;
  const expected = mac(key, expiryMs);
  const givenBuf = Buffer.from(given, 'base64url');
  if (givenBuf.length !== expected.length || !timingSafeEqual(givenBuf, expected)) return false;
  return Number(expiryMs) > now.getTime();
}
