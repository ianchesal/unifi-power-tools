import { CORE_PLAYBOOK } from './core.js';

export interface PlaybookOptions {
  // TRUSTED_ADMIN_NAMES from config: site data, so only ever added at runtime.
  trustedAdminNames: string[];
}

// Phase B has no site-knowledge store, so the playbook ends with this
// placeholder. Phase C replaces it with the active playbook_entries.
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

export function assemblePlaybook(opts: PlaybookOptions): string {
  return [
    CORE_PLAYBOOK,
    trustedAdminsSection(opts.trustedAdminNames),
    NO_SITE_ENTRIES_SECTION,
  ].join('\n\n');
}
