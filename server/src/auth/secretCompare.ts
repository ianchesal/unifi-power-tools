import { timingSafeEqual } from 'node:crypto';

// Constant-time secret comparison. Both sides are padded to the same length so
// timingSafeEqual never throws, then the lengths are compared separately. The
// time taken depends only on the longer input's length, never on where the
// bytes differ. (No hashing: these are transient comparisons, never stored.)
export function secretEquals(given: string, expected: string): boolean {
  if (!given) return false;
  const a = Buffer.from(given, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  const len = Math.max(a.length, b.length);
  const pa = Buffer.alloc(len);
  const pb = Buffer.alloc(len);
  a.copy(pa);
  b.copy(pb);
  const same = timingSafeEqual(pa, pb);
  return same && a.length === b.length;
}
