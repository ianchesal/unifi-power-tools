import { describe, expect, it } from 'vitest';
import { assemblePlaybook, NO_SITE_ENTRIES_SECTION } from '../../src/mcp/playbook/assemble.js';
import { CORE_PLAYBOOK } from '../../src/mcp/playbook/core.js';

const SECTIONS = [
  '## Run procedure',
  '## The context bundle',
  '## Close or attention',
  '## Guardrails site knowledge cannot override',
  '## Recommending UniFi actions',
  '## Rechecks and why_now',
  '## Using history and operator notes',
  '## Known data quirks',
  '## Suggesting improvements',
];

describe('core playbook', () => {
  it('has every required section, in order', () => {
    const idx = SECTIONS.map((s) => CORE_PLAYBOOK.indexOf(s));
    expect(idx.every((i) => i >= 0)).toBe(true);
    expect([...idx].sort((a, b) => a - b)).toEqual(idx);
  });

  it('keeps the operator-approved prefer-attention line verbatim', () => {
    expect(CORE_PLAYBOOK).toContain(
      'When unsure, prefer `attention` (with an honest `risk_level`) only when something was not blocked or the host is internal; already-blocked activity from an external source is a close.'
    );
  });

  it('bounds the run and handles an empty queue', () => {
    expect(CORE_PLAYBOOK).toMatch(/get_pending_analyses`? with `limit: 25`/);
    expect(CORE_PLAYBOOK).toMatch(/queue empty/i);
  });

  it('forbids working around a rejected verdict', () => {
    expect(CORE_PLAYBOOK).toMatch(/never work around a guardrail/i);
  });

  it('names the registry for host+port lessons', () => {
    expect(CORE_PLAYBOOK).toContain('HOMELAB_SERVICES_PATH');
  });

  it('contains no IPv4 literal outside the RFC 5737 documentation ranges', () => {
    const ips = CORE_PLAYBOOK.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? [];
    for (const ip of ips) expect(ip).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\./);
  });
});

describe('core playbook: review fixes', () => {
  it('says guardrails outrank an earlier Not a concern note', () => {
    expect(CORE_PLAYBOOK).toMatch(/guardrails outrank operator notes/i);
  });
  it('tells Claude to fix and resubmit a missing-field rejection', () => {
    expect(CORE_PLAYBOOK).toMatch(/missing or blank field[\s\S]{0,200}resubmit/i);
  });
  it('says not to close when since_last_decision is null', () => {
    expect(CORE_PLAYBOOK).toMatch(/`since_last_decision` is null[\s\S]{0,120}don't close/i);
  });
  it('points the trusted-admin guardrail at the configured list section', () => {
    expect(CORE_PLAYBOOK).toContain('"Configured trusted admins"');
  });
});

describe('assemblePlaybook', () => {
  it('lists the configured trusted admins', () => {
    const text = assemblePlaybook({ trustedAdminNames: ['alice', 'ops-bot'], entries: [] });
    expect(text).toMatch(/## Configured trusted admins[\s\S]*- alice\n- ops-bot/);
  });
  it('says when no trusted admins are configured', () => {
    expect(assemblePlaybook({ trustedAdminNames: [], entries: [] })).toMatch(
      /## Configured trusted admins\n\nNone are configured/
    );
  });
  it('is the core, the trusted-admin section, then the empty site-knowledge section', () => {
    const text = assemblePlaybook({ trustedAdminNames: [], entries: [] });
    expect(text.startsWith(`${CORE_PLAYBOOK}\n\n## Configured trusted admins`)).toBe(true);
    expect(text.endsWith(`\n\n${NO_SITE_ENTRIES_SECTION}`)).toBe(true);
    expect(NO_SITE_ENTRIES_SECTION.startsWith('## Site knowledge')).toBe(true);
    expect(NO_SITE_ENTRIES_SECTION).toMatch(/cited_entries/);
  });
});

describe('core playbook: learning loop', () => {
  const section = (from: string, to: string) =>
    CORE_PLAYBOOK.slice(CORE_PLAYBOOK.indexOf(from), CORE_PLAYBOOK.indexOf(to));
  const procedure = () => section('## Run procedure', '## The context bundle');
  const improvements = () => CORE_PLAYBOOK.slice(CORE_PLAYBOOK.indexOf('## Suggesting improvements'));

  it('run procedure ends with the feedback loop', () => {
    expect(procedure()).toMatch(
      /get_feedback[\s\S]*propose_playbook_change[\s\S]*mark_feedback_considered/
    );
    expect(procedure()).toContain('`list_playbook_proposals`');
  });

  it('still reviews feedback when the queue is empty', () => {
    expect(procedure()).toMatch(/queue empty[\s\S]{0,120}step 5/);
  });

  it('asks for specific, evidenced proposals and keeps registry and rule candidates in the summary', () => {
    expect(improvements()).toContain('`propose_playbook_change`');
    expect(improvements()).toMatch(/finding_ids[\s\S]*history_ids/);
    expect(improvements()).toMatch(/edit or retire/i);
    expect(improvements()).toContain('closed this; consider narrowing it');
    expect(improvements()).toMatch(/Registry candidates/);
    expect(improvements()).toMatch(/Rule candidates/);
    expect(improvements()).not.toMatch(/no tools for changing site knowledge/);
  });

  it('does not promise a rejection that an operator-written entry would pass', () => {
    expect(CORE_PLAYBOOK).not.toContain('it would be rejected anyway');
    expect(CORE_PLAYBOOK).toMatch(
      /unblocked IPS alerts and no operator-written entry covers it, a \`close\` will be rejected/
    );
  });

  it('says shipped defaults cannot justify closing unblocked traffic', () => {
    expect(section('## Guardrails', '## Recommending UniFi actions')).toMatch(
      /shipped defaults can't on their own justify closing traffic that wasn't blocked/
    );
  });
});

describe('assemblePlaybook: site entries', () => {
  const entry = { id: 7, title: 'T', body: 'B', isDefault: false };

  it('lists active entries with ids under Site knowledge', () => {
    const text = assemblePlaybook({
      trustedAdminNames: [],
      entries: [entry, { id: 9, title: 'U', body: 'C', isDefault: false }],
    });
    expect(text).toContain('## Site knowledge');
    expect(text).toContain('### [7] T\n\nB');
    expect(text.endsWith('### [9] U\n\nC')).toBe(true);
    expect(text).toMatch(/## Site knowledge\n\n[^\n]*cited_entries[^\n]*literally/);
    expect(text).not.toContain(NO_SITE_ENTRIES_SECTION);
    expect(text).toContain('## Configured trusted admins');
  });

  it('marks shipped default entries and says what they cannot do', () => {
    const text = assemblePlaybook({
      trustedAdminNames: [],
      entries: [entry, { id: 8, title: 'D', body: 'E', isDefault: true }],
    });
    expect(text).toContain('### [8] D (default)\n\n');
    expect(text).toContain('### [7] T\n\n');
    expect(text.slice(text.lastIndexOf('## Site knowledge'))).toMatch(
      /shipped defaults[^\n]*can't on their own justify closing traffic that wasn't blocked/
    );
  });

  it('falls back to the placeholder with no entries', () => {
    const text = assemblePlaybook({ trustedAdminNames: [], entries: [] });
    expect(text.endsWith(NO_SITE_ENTRIES_SECTION)).toBe(true);
    expect(text).not.toContain('### [');
  });
});
