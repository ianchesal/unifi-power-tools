import { createHash, timingSafeEqual } from 'node:crypto';

// Constant-time secret comparison. Hashing both sides first gives equal-length
// buffers, so timingSafeEqual never throws and length isn't leaked.
export function secretEquals(given: string, expected: string): boolean {
  if (!given) return false;
  const a = createHash('sha256').update(given).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}
