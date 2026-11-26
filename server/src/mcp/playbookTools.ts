import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { markFeedbackConsidered, pendingFeedback } from '../db/findingHistoryStore.js';
import type { LensDb } from '../db/lensDb.js';
import { createProposal, listProposals } from '../db/playbookStore.js';
import { toolError, toolResult } from './tools.js';

// The learning loop's MCP surface. Claude can read feedback and propose changes;
// only the operator, on the dashboard, can apply one.

const IMPORT_KNOWLEDGE_PROMPT = `Import the triage knowledge you hold in your own memory or notes into unifi-siem-lens.

First call \`get_playbook\` and \`list_playbook_proposals\`, so you edit existing entries instead of duplicating them and don't repeat a pending or rejected proposal.

Then take what you know about triaging this network and split it into three groups:

1. **Host and port facts that are always benign.** Print a ready-to-paste \`homelab-services.json\` fragment for the operator, in this shape:

\`\`\`json
{
  "192.0.2.10": {
    "label": "example-host",
    "services": [{ "port": 8080, "name": "example-service", "description": "why this traffic is expected" }]
  }
}
\`\`\`

Add \`wanExposed\` (\`true\`, on the host) only for confirmed port forwards. Never write or edit the file, or any other file, yourself.
2. **Judgment calls.** Make one \`propose_playbook_change\` call for each: specific (named hosts, ports, signatures or CIDRs), with a \`rationale\` saying where the knowledge came from. Use \`op: edit\` with the \`entry_id\` when an entry already covers the topic. Leave the evidence arrays empty unless you have real finding or history ids.
3. **Stale or unverifiable knowledge.** List it for the operator. Don't propose it.

Finish with a summary: the registry fragment, the proposals you made (they take effect only when the operator approves them) and the stale list.`;

export function registerPlaybookTools(server: McpServer, lensDb: LensDb): void {
  server.tool(
    'get_feedback',
    "The operator's decisions (closed as handled, closed as not a concern, reopened) that no run has reviewed yet, oldest first.",
    { limit: z.number().int().min(1).max(100).default(50) },
    async (p) => {
      try {
        return toolResult(pendingFeedback(lensDb, p.limit));
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'mark_feedback_considered',
    'Mark feedback rows (history ids from get_feedback) as reviewed, so they are not returned again.',
    { ids: z.array(z.number().int()) },
    async (p) => {
      try {
        return toolResult({
          marked: markFeedbackConsidered(lensDb, p.ids, new Date().toISOString()),
        });
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'propose_playbook_change',
    'Propose adding, editing or retiring a site-knowledge entry. It stays pending until the operator accepts it on the dashboard. edit and retire need entry_id; for retire, repeat the current title and body of the entry.',
    {
      op: z.enum(['add', 'edit', 'retire']),
      entry_id: z.number().int().optional(),
      title: z.string(),
      body: z.string(),
      rationale: z.string(),
      evidence: z.object({
        finding_ids: z.array(z.number().int()),
        history_ids: z.array(z.number().int()),
      }),
    },
    async (p) => {
      try {
        if (p.rationale.trim() === '') throw new Error('rationale must not be blank');
        const proposal = createProposal(
          lensDb,
          {
            op: p.op,
            entry_id: p.entry_id,
            title: p.title,
            body: p.body,
            rationale: p.rationale,
            evidence: p.evidence,
            proposed_by: 'ai',
          },
          new Date().toISOString()
        );
        return toolResult(proposal);
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'list_playbook_proposals',
    'List playbook change proposals, newest first, optionally by status.',
    { status: z.enum(['pending', 'accepted', 'rejected']).optional() },
    async (p) => {
      try {
        return toolResult(listProposals(lensDb, { status: p.status }));
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.registerPrompt(
    'import_knowledge',
    {
      title: 'Import triage knowledge',
      description:
        'Move triage knowledge from your memory or notes into the homelab registry and playbook proposals.',
    },
    () => ({
      messages: [
        {
          role: 'user' as const,
          content: { type: 'text' as const, text: IMPORT_KNOWLEDGE_PROMPT },
        },
      ],
    })
  );
}
