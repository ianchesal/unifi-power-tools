import { CORE_PLAYBOOK } from './core.js';

// Phase B has no site-knowledge store, so the playbook is the core plus this
// placeholder. Phase C replaces it with the active playbook_entries.
export const NO_SITE_ENTRIES_SECTION = `## Site knowledge

No site entries are active on this install yet. Leave \`cited_entries\` empty: any cited id is rejected.`;

export function assemblePlaybook(): string {
  return `${CORE_PLAYBOOK}\n\n${NO_SITE_ENTRIES_SECTION}`;
}
