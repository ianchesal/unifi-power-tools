import { type ReactNode, useEffect, useRef, useState } from 'react';
import { errorMessage, fetchJson, postJson, putJson } from '../api';
import { relativeTime } from '../format';
import type {
  EvidenceFinding,
  HistoryEntry,
  HomelabHost,
  Playbook,
  PlaybookEntry,
  PlaybookProposal,
  ProposalOp,
  ProposedBy,
} from '../types';
import { HistoryTimeline } from './HistoryTimeline';
import { NoteBox } from './NoteBox';

const OP_LABELS: Record<ProposalOp, string> = { add: 'Add', edit: 'Edit', retire: 'Retire' };
const PROPOSER_LABELS: Record<ProposedBy, string> = { ai: 'AI', human: 'you', default: 'shipped default' };

// The last failed action. It lives on the page so it survives the reload that
// follows a failure, even when that reload removes the card it came from.
interface Failure {
  key: string;
  message: string;
}

interface ActionProps {
  failure: Failure | null;
  onDone: () => void;
  onFailed: (failure: Failure) => void;
  onClearError: () => void;
}

// Busy state and error reporting for one card's writes.
function useAction(key: string, { failure, onDone, onFailed, onClearError }: ActionProps) {
  const [busy, setBusy] = useState(false);
  const run = async (action: () => Promise<unknown>, after: () => void) => {
    onClearError();
    setBusy(true);
    try {
      await action();
      after();
      onDone();
    } catch (err) {
      onFailed({ key, message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  return { busy, run, error: failure?.key === key ? failure.message : null };
}

function Timestamp({ iso }: { iso: string }) {
  return (
    <span className="timestamp" title={iso}>
      {relativeTime(iso) ?? iso}
    </span>
  );
}

function EntryText({ title, body }: { title: string; body: string }) {
  return (
    <div className="entry-text">
      <h3 className="attention-headline">{title}</h3>
      <p className="analysis-body">{body}</p>
    </div>
  );
}

function EntryForm({
  initial = { title: '', body: '' },
  submitLabel,
  busy,
  onSubmit,
  onCancel,
}: {
  initial?: { title: string; body: string };
  submitLabel: string;
  busy: boolean;
  onSubmit: (title: string, body: string) => void;
  onCancel: () => void;
}) {
  const [title, setTitle] = useState(initial.title);
  const [body, setBody] = useState(initial.body);
  const blank = title.trim() === '' || body.trim() === '';
  return (
    <form
      className="note-box"
      onSubmit={(e) => {
        e.preventDefault();
        if (!busy && !blank) onSubmit(title.trim(), body.trim());
      }}
    >
      <input
        className="note-input"
        aria-label="Title"
        placeholder="Title"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
      />
      <textarea
        className="note-input"
        aria-label="Body"
        placeholder="Name the hosts, ports, signatures or CIDRs this covers, and what to do"
        rows={5}
        value={body}
        onChange={(e) => setBody(e.target.value)}
      />
      <div className="note-actions">
        <button className="btn btn-primary" type="submit" disabled={busy || blank}>
          {busy ? 'Saving…' : submitLabel}
        </button>
        <button className="btn btn-ghost" type="button" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

// One finding behind a proposal; its history is fetched on first expand.
function Evidence({ finding }: { finding: EvidenceFinding }) {
  const [open, setOpen] = useState(false);
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!open || entries !== null) return;
    fetchJson<HistoryEntry[]>(`/api/findings/${finding.id}/history`)
      .then((rows) => {
        setEntries(rows);
        setFailed(false);
      })
      .catch(() => setFailed(true));
  }, [open, entries, finding.id]);

  return (
    <details className="history" onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary>
        Finding #{finding.id} · {finding.entity_type.replace('_', ' ')}{' '}
        <span className="mono evidence-key">{finding.entity_key}</span> · {finding.status}
      </summary>
      {failed ? (
        <p className="muted-line">Couldn't load history.</p>
      ) : entries === null ? (
        <p className="muted-line">Loading…</p>
      ) : (
        <HistoryTimeline entries={entries} />
      )}
    </details>
  );
}

function ProposalChange({ proposal }: { proposal: PlaybookProposal }) {
  const { op, current } = proposal;
  if (op === 'add') return <EntryText title={proposal.title} body={proposal.body} />;
  if (!current) {
    return <p className="action-error">The entry this changes no longer exists; reject this proposal.</p>;
  }
  if (op === 'retire') return <EntryText title={current.title} body={current.body} />;
  return (
    <>
      {current.status === 'retired' && (
        <p className="muted-line">This entry is retired. Accepting reactivates it.</p>
      )}
      <div className="diff-grid">
        <div className="diff-col">
          <span className="diff-label">Current</span>
          <EntryText title={current.title} body={current.body} />
        </div>
        <div className="diff-col proposed">
          <span className="diff-label">Proposed</span>
          <EntryText title={proposal.title} body={proposal.body} />
        </div>
      </div>
    </>
  );
}

function ProposalCard({ proposal, ...actions }: { proposal: PlaybookProposal } & ActionProps) {
  const [mode, setMode] = useState<'edit' | 'reject' | null>(null);
  const { busy, run, error } = useAction(`proposal-${proposal.id}`, actions);
  const url = `/api/playbook/proposals/${proposal.id}`;
  // A proposal may cite the same finding twice.
  const evidence = [...new Map(proposal.evidence_findings.map((f) => [f.id, f])).values()];
  const close = () => {
    actions.onClearError();
    setMode(null);
  };
  const open = (next: 'edit' | 'reject') => {
    actions.onClearError();
    setMode(next);
  };
  const accept = (edits: { edited_title?: string; edited_body?: string }) =>
    run(() => postJson(`${url}/accept`, edits), close);

  return (
    <div className="finding-card">
      <div className="analysis-head">
        <span className="playbook-tag">
          {OP_LABELS[proposal.op]}
          {proposal.entry_id !== null && ` entry #${proposal.entry_id}`}
        </span>
        <span className="analysis-source">proposed by {PROPOSER_LABELS[proposal.proposed_by]}</span>
        <span className="spacer" />
        <Timestamp iso={proposal.created_at} />
      </div>
      {proposal.rationale && <p className="analysis-body">{proposal.rationale}</p>}
      <ProposalChange proposal={proposal} />
      {proposal.proposed_by === 'default' && (
        <p className="muted-line">
          Accept keeps this as shipped default text, which can't by itself justify closing unblocked traffic. Edit &amp;
          accept with your own changes makes it yours.
        </p>
      )}
      {evidence.length > 0 && (
        <div className="evidence-list">
          <span className="diff-label">Evidence</span>
          {evidence.map((f) => (
            <Evidence key={f.id} finding={f} />
          ))}
        </div>
      )}
      <div className="finding-actions">
        <button className="btn btn-primary" type="button" disabled={busy} onClick={() => accept({})}>
          Accept
        </button>
        {/* A retire applies no text, so there is nothing to edit. */}
        {proposal.op !== 'retire' && (
          <button className="btn btn-ghost" type="button" disabled={busy} onClick={() => open('edit')}>
            Edit &amp; accept
          </button>
        )}
        <button className="btn btn-danger-ghost" type="button" disabled={busy} onClick={() => open('reject')}>
          Reject
        </button>
      </div>
      {mode === 'edit' && (
        <EntryForm
          initial={proposal}
          submitLabel="Accept edited"
          busy={busy}
          onSubmit={(title, body) => accept({ edited_title: title, edited_body: body })}
          onCancel={close}
        />
      )}
      {mode === 'reject' && (
        <NoteBox
          placeholder="Why reject it? (optional)"
          busy={busy}
          onConfirm={(note) => run(() => postJson(`${url}/reject`, note ? { note } : {}), close)}
          onCancel={close}
        />
      )}
      {error && <p className="action-error">{error}</p>}
    </div>
  );
}

function EntryCard({
  entry,
  linked,
  ...actions
}: { entry: PlaybookEntry; linked: boolean } & ActionProps) {
  const [mode, setMode] = useState<'edit' | 'retire' | null>(null);
  const { busy, run, error } = useAction(`entry-${entry.id}`, actions);
  const retired = entry.status === 'retired';
  const close = () => {
    actions.onClearError();
    setMode(null);
  };
  const open = (next: 'edit' | 'retire') => {
    actions.onClearError();
    setMode(next);
  };

  return (
    <div id={`entry-${entry.id}`} className={`finding-card playbook-entry${linked ? ' is-linked' : ''}`}>
      <div className="analysis-head">
        <span className="timestamp">#{entry.id}</span>
        {/* The server reports every retired entry as default, so label active ones only. */}
        {!retired && entry.is_default && <span className="playbook-tag muted">default</span>}
        {retired && <span className="playbook-tag muted">retired</span>}
        <span className="spacer" />
        <span className="timestamp" title={entry.updated_at}>
          updated {relativeTime(entry.updated_at) ?? entry.updated_at}
        </span>
      </div>
      {mode === 'edit' ? (
        <>
          {retired && <p className="muted-line">Saving reactivates this entry.</p>}
          <EntryForm
            initial={entry}
            submitLabel={retired ? 'Save and reactivate' : 'Save'}
            busy={busy}
            onSubmit={(title, body) =>
              run(() => putJson(`/api/playbook/entries/${entry.id}`, { title, body }), close)
            }
            onCancel={close}
          />
        </>
      ) : (
        <EntryText title={entry.title} body={entry.body} />
      )}
      {mode !== 'edit' && (
        <div className="finding-actions">
          <button className="btn btn-ghost" type="button" disabled={busy} onClick={() => open('edit')}>
            Edit
          </button>
          {!retired && (
            <button className="btn btn-danger-ghost" type="button" disabled={busy} onClick={() => open('retire')}>
              Retire
            </button>
          )}
        </div>
      )}
      {mode === 'retire' && !retired && (
        <NoteBox
          placeholder="Why retire it? (optional)"
          busy={busy}
          onConfirm={(note) =>
            run(() => postJson(`/api/playbook/entries/${entry.id}/retire`, note ? { note } : {}), close)
          }
          onCancel={close}
        />
      )}
      {error && <p className="action-error">{error}</p>}
    </div>
  );
}

function AddEntry(actions: ActionProps) {
  const [adding, setAdding] = useState(false);
  const { busy, run, error } = useAction('add-entry', actions);
  const close = () => {
    actions.onClearError();
    setAdding(false);
  };
  return (
    <>
      {adding ? (
        <div className="finding-card">
          <EntryForm
            submitLabel="Add entry"
            busy={busy}
            onSubmit={(title, body) => run(() => postJson('/api/playbook/proposals', { title, body }), close)}
            onCancel={close}
          />
          {error && <p className="action-error">{error}</p>}
        </div>
      ) : (
        <div className="finding-actions">
          <button className="btn btn-primary" type="button" onClick={() => setAdding(true)}>
            Add entry
          </button>
        </div>
      )}
    </>
  );
}

// Collapsed unless the page was opened on a link to one of these entries.
function RetiredEntries({ initiallyOpen, count, children }: { initiallyOpen: boolean; count: number; children: ReactNode }) {
  const [open, setOpen] = useState(initiallyOpen);
  return (
    <details className="history" open={open} onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary>Retired ({count})</summary>
      <div className="findings-list">{children}</div>
    </details>
  );
}

function ChangeLog({ decided }: { decided: PlaybookProposal[] }) {
  if (decided.length === 0) return <p className="muted-line">No changes yet.</p>;
  return (
    <ol className="change-log">
      {decided.map((p) => (
        <li key={p.id}>
          {p.decided_at ? <Timestamp iso={p.decided_at} /> : <span />}
          <span className={`change-status ${p.status}`}>{p.status}</span>
          <span className="analysis-source">
            {OP_LABELS[p.op]}
            {p.entry_id !== null && ` #${p.entry_id}`} · by {PROPOSER_LABELS[p.proposed_by]}
          </span>
          <span className="history-summary">
            {p.title}
            {p.decision_note && <span className="history-note"> “{p.decision_note}”</span>}
          </span>
        </li>
      ))}
    </ol>
  );
}

function RegistryHost({ ip, host }: { ip: string; host: HomelabHost }) {
  // The file is hand-written and not validated by the server.
  const services = host.services ?? [];
  const notes = host.notes ?? [];
  return (
    <div className="finding-card">
      <div className="analysis-head">
        <span className="entity-key">{host.label}</span>
        <span className="timestamp">{ip}</span>
        <span className={`playbook-tag${host.wanExposed ? ' exposed' : ' muted'}`}>
          {host.wanExposed ? 'WAN exposed' : 'not marked WAN exposed'}
        </span>
      </div>
      {services.length > 0 && (
        <ul className="registry-list">
          {services.map((s) => (
            <li key={`${s.port}-${s.name}`}>
              <span className="mono">{s.port}</span> {s.name}
              {s.description && ` — ${s.description}`}
            </li>
          ))}
        </ul>
      )}
      {notes.map((n) => (
        <p key={n} className="analysis-body">
          {n}
        </p>
      ))}
    </div>
  );
}

function linkedEntryId(): number | null {
  const match = /^#entry-(\d+)$/.exec(window.location.hash);
  return match ? Number(match[1]) : null;
}

export function PlaybookPage() {
  const [data, setData] = useState<{ playbook: Playbook; proposals: PlaybookProposal[] } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [linkedId] = useState(linkedEntryId);
  const scrolled = useRef(false);

  // biome-ignore lint/correctness/useExhaustiveDependencies: reloadKey drives a manual reload, not a data dependency
  useEffect(() => {
    // A slower, older load must not overwrite a newer one.
    let stale = false;
    Promise.all([
      fetchJson<Playbook>('/api/playbook'),
      fetchJson<PlaybookProposal[]>('/api/playbook/proposals'),
    ])
      .then(([playbook, proposals]) => {
        if (stale) return;
        setData({ playbook, proposals });
        setLoadError(null);
      })
      .catch((e) => {
        if (!stale) setLoadError(errorMessage(e));
      });
    return () => {
      stale = true;
    };
  }, [reloadKey]);

  // The browser can't jump to #entry-N itself: the entry isn't rendered yet
  // when the page loads.
  useEffect(() => {
    if (scrolled.current || !data || linkedId === null) return;
    scrolled.current = true;
    document.getElementById(`entry-${linkedId}`)?.scrollIntoView({ block: 'center' });
  }, [data, linkedId]);

  const reload = () => setReloadKey((k) => k + 1);
  const actions: ActionProps = {
    failure,
    onDone: () => {
      setFailure(null);
      reload();
    },
    onFailed: (f) => {
      setFailure(f);
      reload();
    },
    onClearError: () => setFailure(null),
  };

  const entries = data?.playbook.entries ?? [];
  const active = entries.filter((e) => e.status === 'active');
  const retired = entries.filter((e) => e.status === 'retired');
  const pending = data?.proposals.filter((p) => p.status === 'pending') ?? [];
  const decided = (data?.proposals.filter((p) => p.status !== 'pending') ?? []).sort(
    (a, b) => (b.decided_at ?? '').localeCompare(a.decided_at ?? '') || b.id - a.id
  );
  const hosts = Object.entries(data?.playbook.registry ?? {});
  // A proposal decided elsewhere disappears on reload; keep saying why the action failed.
  const orphanFailure =
    failure?.key.startsWith('proposal-') && !pending.some((p) => failure.key === `proposal-${p.id}`)
      ? failure
      : null;

  const entryCard = (e: PlaybookEntry) => (
    <EntryCard key={e.id} entry={e} linked={e.id === linkedId} {...actions} />
  );

  return (
    <div className="main">
      <div className="page-head">
        <div>
          <h1 className="page-title">Playbook</h1>
          <p className="page-subtitle">Site knowledge the AI triage relies on. Nothing changes until you approve it.</p>
        </div>
        <a href="/">Back to dashboard</a>
      </div>

      {loadError && <p className="action-error">{loadError}</p>}
      {!data && !loadError && <p className="muted-line">Loading…</p>}

      {data && (
        <>
          <div className="section">
            <div className="section-head">
              <h2 className="section-title">Pending proposals</h2>
              <span className="section-count">{pending.length}</span>
            </div>
            {orphanFailure && <p className="action-error">{orphanFailure.message}</p>}
            {pending.length === 0 && <p className="muted-line">No proposals waiting.</p>}
            <div className="findings-list">
              {pending.map((p) => (
                <ProposalCard key={p.id} proposal={p} {...actions} />
              ))}
            </div>
          </div>

          <div className="section">
            <div className="section-head">
              <h2 className="section-title">Active entries</h2>
              <span className="section-count">{active.length}</span>
            </div>
            <AddEntry {...actions} />
            {active.length === 0 && <p className="muted-line">No active entries.</p>}
            <div className="findings-list">{active.map(entryCard)}</div>
            {retired.length > 0 && (
              <RetiredEntries count={retired.length} initiallyOpen={retired.some((e) => e.id === linkedId)}>
                {retired.map(entryCard)}
              </RetiredEntries>
            )}
          </div>

          <div className="section">
            <div className="section-head">
              <h2 className="section-title">Change log</h2>
              <span className="section-count">{decided.length}</span>
            </div>
            <ChangeLog decided={decided} />
          </div>

          <div className="section">
            <div className="section-head">
              <h2 className="section-title">Homelab registry</h2>
              <span className="section-count">read-only</span>
            </div>
            {hosts.length === 0 && (
              <p className="muted-line">
                No hosts listed: point <span className="mono">HOMELAB_SERVICES_PATH</span> at a JSON file of your LAN
                hosts and services, then restart lens.
              </p>
            )}
            <div className="findings-list">
              {hosts.map(([ip, host]) => (
                <RegistryHost key={ip} ip={ip} host={host} />
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
