import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// server/.env.example is what the README tells Docker users to copy to .env.
// An env file overrides the image's ENV lines, so it must not set values the
// image depends on (paths under /data, binding 0.0.0.0).
const IMAGE_OWNED = ['HOST', 'EVENTS_DB_PATH', 'LENS_DB_PATH'];

function assignedKeys(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#') && l.includes('='))
    .map((l) => l.slice(0, l.indexOf('=')).trim());
}

describe('server/.env.example', () => {
  const keys = assignedKeys(readFileSync(new URL('../.env.example', import.meta.url), 'utf8'));

  it.each(IMAGE_OWNED)('leaves %s commented out so the Docker image value stands', (k) => {
    expect(keys).not.toContain(k);
  });

  it('still sets the two required secrets as empty placeholders', () => {
    expect(keys).toContain('MCP_SECRET');
    expect(keys).toContain('DASHBOARD_PASSWORD');
  });
});
