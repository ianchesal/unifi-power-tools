import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { decisionWindowStart } from '../analysis/findings.js';
import { applyAiVerdict } from '../analysis/pipeline.js';
import { PHASE_A_ACTIVE_ENTRY_IDS } from '../analysis/verdict.js';
import {
  getAnalysisRequest,
  getPendingAnalysisRequests,
  updateRequestContext,
} from '../db/analysisRequestsStore.js';
import { getFindingById } from '../db/findingsStore.js';
import { countUnblockedIpsAlerts } from '../db/sinkQueries.js';
import { type AnalysisDeps, buildAnalysisContext } from './context.js';

function toolResult(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

function toolError(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  return {
    content: [{ type: 'text' as const, text: `Error: ${message}` }],
    isError: true as const,
  };
}

export function registerAnalysisTools(server: McpServer, deps: AnalysisDeps): void {
  const { lensDb, sinkDb } = deps;

  server.tool(
    'get_pending_analyses',
    'List pending analysis requests, highest severity first.',
    { limit: z.number().int().min(1).optional() },
    async (p) => {
      try {
        const rows = getPendingAnalysisRequests(lensDb, { limit: p.limit });
        return toolResult(rows.map(({ context: _context, ...rest }) => rest));
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'get_analysis_context',
    'Get the full context bundle for one analysis request: the finding, its history, prior analyses, recent events and activity since the last decision.',
    { id: z.number().int() },
    async (p) => {
      try {
        const request = getAnalysisRequest(lensDb, p.id);
        if (!request) throw new Error(`Analysis request ${p.id} not found`);
        const finding = getFindingById(lensDb, request.finding_id);
        if (!finding) throw new Error(`Finding ${request.finding_id} not found`);
        const bundle = await buildAnalysisContext(deps, request, finding, new Date().toISOString());
        // The store only writes while the request is still pending.
        updateRequestContext(lensDb, request.id, bundle);
        return toolResult(bundle);
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'submit_analysis',
    'Submit a verdict for a pending analysis request: close (benign) or attention (needs a human). Closing is rejected while unblocked IPS alerts exist since the last decision, unless a playbook entry is cited.',
    {
      id: z.number().int(),
      verdict: z.enum(['close', 'attention']),
      risk_level: z.enum(['low', 'medium', 'high']),
      summary: z.string(),
      reasoning: z.string(),
      recommended_action: z.string().optional(),
      why_now: z.string().optional(),
      cited_entries: z.array(z.number().int()).optional(),
    },
    async ({ id, ...input }) => {
      try {
        const request = getAnalysisRequest(lensDb, id);
        const finding = request ? getFindingById(lensDb, request.finding_id) : null;
        let unblocked: number | null = null;
        if (sinkDb && finding) {
          try {
            unblocked = countUnblockedIpsAlerts(
              sinkDb,
              finding.entity_type,
              finding.entity_key,
              decisionWindowStart(finding)
            );
          } catch (err) {
            // e.g. a pre-v1.0.3 sink for a client finding: treat as unavailable.
            console.error('Unblocked IPS alert count failed:', err);
          }
        }
        // applyAiVerdict reports a missing/answered/cancelled request itself.
        const result = applyAiVerdict(
          lensDb,
          id,
          input,
          { unblockedIpsAlertsSinceDecision: unblocked, activeEntryIds: PHASE_A_ACTIVE_ENTRY_IDS },
          new Date().toISOString()
        );
        return toolResult(result);
      } catch (e) {
        return toolError(e);
      }
    }
  );
}
