import { useEffect, useState } from 'react';
import { errorMessage, fetchJson, postJson } from '../api';
import { relativeTime } from '../format';
import type { ClosedBy, Finding } from '../types';
import { FindingIdentity } from './FindingIdentity';
import { NoteBox } from './NoteBox';

const PAGE_SIZE = 20;

const CLOSED_BY_OPTIONS: { value: '' | ClosedBy; label: string }[] = [
  { value: '', label: 'All' },
  { value: 'rule', label: 'Rule' },
  { value: 'ai', label: 'AI' },
  { value: 'human', label: 'Human' },
  { value: 'system', label: 'System' },
];

const CLOSED_BY_LABELS: Record<ClosedBy, string> = { rule: 'rule', ai: 'AI', human: 'human', system: 'system' };

export function ClosedList({ refreshKey, onChanged }: { refreshKey: number; onChanged: () => void }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [closedBy, setClosedBy] = useState<'' | ClosedBy>('');
  const [searchInput, setSearchInput] = useState('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [failure, setFailure] = useState<{ id: number; message: string } | null>(null);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey/reloadKey drive a manual reload, not a data dependency
  useEffect(() => {
    const params = new URLSearchParams({ view: 'closed', limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) });
    if (closedBy) params.set('closed_by', closedBy);
    if (q) params.set('q', q);
    fetchJson<{ items: Finding[]; total: number }>(`/api/findings?${params}`)
      .then(({ items, total: t }) => {
        setFindings(items);
        setTotal(t);
        setLoadError(null);
      })
      .catch((e) => setLoadError(String(e)));
  }, [refreshKey, reloadKey, closedBy, q, page]);

  const handleChanged = () => {
    setFailure(null);
    onChanged();
  };
  const handleFailed = (id: number, message: string) => {
    setFailure({ id, message });
    setReloadKey((k) => k + 1);
  };

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const rangeStart = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const rangeEnd = Math.min(total, page * PAGE_SIZE + findings.length);
  const orphanFailure = failure && !findings.some((f) => f.id === failure.id) ? failure : null;

  return (
    <>
      <div className="closed-filters">
        <select
          className="closed-select"
          aria-label="Closed by"
          value={closedBy}
          onChange={(e) => {
            setClosedBy(e.target.value as '' | ClosedBy);
            setPage(0);
          }}
        >
          {CLOSED_BY_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <input
          className="closed-search"
          type="search"
          placeholder="Search key or reason, press Enter"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              setQ(searchInput.trim());
              setPage(0);
            }
          }}
        />
        <span className="section-count">{total > 0 ? `${rangeStart}–${rangeEnd} of ${total}` : '0 shown'}</span>
      </div>

      {loadError && <p className="action-error">{loadError}</p>}
      {orphanFailure && <p className="action-error">Finding #{orphanFailure.id}: {orphanFailure.message}</p>}
      {!loadError && findings.length === 0 && <p className="muted-line">No closed findings in this view.</p>}

      <div className="findings-list">
        {findings.map((f) => (
          <ClosedRow
            key={f.id}
            finding={f}
            error={failure?.id === f.id ? failure.message : null}
            onChanged={handleChanged}
            onFailed={(message) => handleFailed(f.id, message)}
          />
        ))}
      </div>

      {total > 0 && (
        <div className="pagination">
          <button className="btn btn-ghost" type="button" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
            Previous
          </button>
          <span className="pagination-status">
            Page {page + 1} of {pageCount}
          </span>
          <button className="btn btn-ghost" type="button" disabled={page + 1 >= pageCount} onClick={() => setPage((p) => p + 1)}>
            Next
          </button>
        </div>
      )}
    </>
  );
}

function ClosedRow({
  finding,
  error,
  onChanged,
  onFailed,
}: {
  finding: Finding;
  error: string | null;
  onChanged: () => void;
  onFailed: (message: string) => void;
}) {
  const [reopening, setReopening] = useState(false);
  const [busy, setBusy] = useState(false);

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await action();
      setReopening(false);
      onChanged();
    } catch (err) {
      onFailed(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const closedAgo = relativeTime(finding.closed_at);
  const badge = finding.closed_by ? (
    <span className={`status-badge closed-by ${finding.closed_by}`}>{CLOSED_BY_LABELS[finding.closed_by]}</span>
  ) : null;

  return (
    <div className="finding-card">
      <FindingIdentity finding={finding} badge={badge} />
      {finding.closed_reason && <p className="analysis-body">{finding.closed_reason}</p>}
      <div className="finding-actions">
        <button className="btn btn-danger-ghost" type="button" disabled={busy} onClick={() => setReopening(true)}>
          This was wrong
        </button>
        <button
          className="btn btn-ghost"
          type="button"
          disabled={busy}
          onClick={() => run(() => postJson(`/api/findings/${finding.id}/reanalyze`))}
        >
          Re-analyze
        </button>
        <span className="spacer" />
        {closedAgo && <span className="timestamp">closed {closedAgo}</span>}
      </div>
      {reopening && (
        <NoteBox
          placeholder="What did the AI or rule get wrong?"
          required
          busy={busy}
          onConfirm={(note) => run(() => postJson(`/api/findings/${finding.id}/reopen`, { note }))}
          onCancel={() => setReopening(false)}
        />
      )}
      {error && <p className="action-error">{error}</p>}
    </div>
  );
}
