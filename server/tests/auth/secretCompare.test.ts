import { describe, expect, it } from 'vitest';
import { secretEquals } from '../../src/auth/secretCompare.js';

describe('secretEquals', () => {
  it('is true for equal secrets', () => {
    expect(secretEquals('s3cret', 's3cret')).toBe(true);
  });

  it('is false for different secrets of the same length', () => {
    expect(secretEquals('s3cret', 's3creT')).toBe(false);
  });

  it('is false for different lengths without throwing', () => {
    expect(secretEquals('short', 'a-much-longer-secret')).toBe(false);
  });

  it('is false for an empty given value', () => {
    expect(secretEquals('', 's3cret')).toBe(false);
  });
});
