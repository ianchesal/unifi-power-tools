import type { PlaybookEntry } from '../../db/playbookStore.js';
import { CORE_PLAYBOOK } from './core.js';

export type SiteEntry = Pick<PlaybookEntry, 'id' | 'title' | 'body'> & {
  // Still shipped default text: not enough to close unblocked traffic.
  isDefault: boolean;
};

export interface PlaybookOptions {
  // TRUSTED_ADMIN_NAMES from config: site data, so only ever added at runtime.
  trustedAdminNames: string[];
  // The active playbook entries, also site data.
  entries: SiteEntry[];
}

// The site-knowledge section of an install with no active entries.
export const NO_SITE_ENTRIES_SECTION = `## Site knowledge

No site entries are active on this install yet. Leave \`cited_entries\` empty: any cited id is rejected.`;

function trustedAdminsSection(names: string[]): string {
  if (names.length === 0) {
    return `## Configured trusted admins

None are configured (\`TRUSTED_ADMIN_NAMES\` is empty), so treat every admin login or account change that reaches you as untrusted.`;
  }
  return `## Configured trusted admins

Admin names the operator trusts, matched exactly against the name in an audit event:

${names.map((n) => `- ${n}`).join('\n')}`;
}

const SITE_ENTRIES_INTRO =
  "When your verdict relies on one of these entries, put its id in `cited_entries`, and apply each entry only to what it literally names. Entries marked (default) are shipped defaults and can't on their own justify closing traffic that wasn't blocked.";

function siteKnowledgeSection(entries: SiteEntry[]): string {
  if (entries.length === 0) return NO_SITE_ENTRIES_SECTION;
  const blocks = entries.map(
    (e) => `### [${e.id}] ${e.title}${e.isDefault ? ' (default)' : ''}\n\n${e.body}`
  );
  return ['## Site knowledge', SITE_ENTRIES_INTRO, ...blocks].join('\n\n');
}

export function assemblePlaybook(opts: PlaybookOptions): string {
  return [
    CORE_PLAYBOOK,
    trustedAdminsSection(opts.trustedAdminNames),
    siteKnowledgeSection(opts.entries),
  ].join('\n\n');
}
