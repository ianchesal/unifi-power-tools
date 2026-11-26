import { type Request, type Response, Router } from 'express';
import { z } from 'zod';
import { getFindingById } from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';
import {
  acceptProposal,
  humanChange,
  listEntries,
  listProposals,
  operatorBackedEntryIds,
  type PlaybookEntry,
  type PlaybookProposal,
  ProposalError,
  type ProposalStatus,
  rejectProposal,
} from '../db/playbookStore.js';
import type { HomelabRegistry } from '../enrichment/homelabServices.js';

const STATUSES = ['pending', 'accepted', 'rejected'] as const;
const ERROR_STATUS = { not_found: 404, conflict: 409, invalid: 400 } as const;

const text = z.string().trim().min(1);
const EntryBody = z.object({ title: text, body: text });
const AcceptBody = z.object({ edited_title: text.optional(), edited_body: text.optional() });
const NoteBody = z.object({ note: z.string().trim().optional() });

// A proposal with what the operator needs to judge it: the findings behind it,
// and the entry it would change.
function withContext(db: LensDb, proposal: PlaybookProposal, entries: Map<number, PlaybookEntry>) {
  const evidenceFindings = proposal.evidence.finding_ids.flatMap((id) => {
    const f = getFindingById(db, id);
    return f
      ? [{ id, entity_type: f.entity_type, entity_key: f.entity_key, status: f.status }]
      : [];
  });
  const entry = proposal.entry_id === null ? undefined : entries.get(proposal.entry_id);
  return {
    ...proposal,
    evidence_findings: evidenceFindings,
    current: entry ? { title: entry.title, body: entry.body, status: entry.status } : null,
  };
}

// Every write requires a JSON body, even an empty object: a cross-site page
// can't send one without a CORS preflight, which this API never grants.
function parseBody<T>(schema: z.ZodType<T>, req: Request, res: Response, error: string): T | null {
  const parsed = schema.safeParse(req.body);
  if (parsed.success) return parsed.data;
  res.status(400).json({ error });
  return null;
}

function parseId(req: Request, res: Response): number | null {
  const raw = String(req.params.id);
  if (/^\d+$/.test(raw)) return Number(raw);
  res.status(400).json({ error: 'id must be an integer' });
  return null;
}

// Runs a playbook write, mapping the store's errors to HTTP statuses.
function act(res: Response, status: number, run: (nowIso: string) => unknown): void {
  try {
    res.status(status).json(run(new Date().toISOString()));
  } catch (err) {
    if (!(err instanceof ProposalError)) throw err;
    res.status(ERROR_STATUS[err.code]).json({ error: err.message });
  }
}

export function createPlaybookRouter(lensDb: LensDb, homelabServices: HomelabRegistry): Router {
  const router = Router();

  router.get('/', (_req, res) => {
    const backed = operatorBackedEntryIds(lensDb);
    const entries = [
      ...listEntries(lensDb, { status: 'active' }),
      ...listEntries(lensDb, { status: 'retired' }),
    ].map((e) => ({ ...e, is_default: !backed.has(e.id) }));
    res.json({ entries, registry: homelabServices });
  });

  router.get('/proposals', (req, res) => {
    const status = req.query.status;
    if (status !== undefined && !(STATUSES as readonly unknown[]).includes(status)) {
      res.status(400).json({ error: `status must be one of ${STATUSES.join(', ')}` });
      return;
    }
    const entries = new Map(listEntries(lensDb).map((e) => [e.id, e]));
    const proposals = listProposals(lensDb, { status: status as ProposalStatus | undefined });
    res.json(proposals.map((p) => withContext(lensDb, p, entries)));
  });

  // The operator's own add, edit and retire are recorded as accepted proposals.
  router.post('/proposals', (req, res) => {
    const body = parseBody(EntryBody, req, res, 'title and body are required');
    if (!body) return;
    act(res, 201, (now) => humanChange(lensDb, { op: 'add', ...body }, now));
  });

  router.post('/proposals/:id/accept', (req, res) => {
    const id = parseId(req, res);
    if (id === null) return;
    const body = parseBody(AcceptBody, req, res, 'edited_title and edited_body must not be blank');
    if (!body) return;
    const edits = { title: body.edited_title, body: body.edited_body };
    act(res, 200, (now) => acceptProposal(lensDb, id, edits, now));
  });

  router.post('/proposals/:id/reject', (req, res) => {
    const id = parseId(req, res);
    if (id === null) return;
    const body = parseBody(NoteBody, req, res, 'note must be a string');
    if (!body) return;
    act(res, 200, (now) => rejectProposal(lensDb, id, body.note || null, now));
  });

  router.put('/entries/:id', (req, res) => {
    const id = parseId(req, res);
    if (id === null) return;
    const body = parseBody(EntryBody, req, res, 'title and body are required');
    if (!body) return;
    act(res, 200, (now) => humanChange(lensDb, { op: 'edit', entry_id: id, ...body }, now));
  });

  router.post('/entries/:id/retire', (req, res) => {
    const id = parseId(req, res);
    if (id === null) return;
    const body = parseBody(NoteBody, req, res, 'note must be a string');
    if (!body) return;
    const rationale = body.note || 'Retired from the dashboard';
    act(res, 200, (now) => humanChange(lensDb, { op: 'retire', entry_id: id, rationale }, now));
  });

  return router;
}
