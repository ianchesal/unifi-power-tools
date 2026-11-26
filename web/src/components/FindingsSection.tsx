import { useEffect, useState } from 'react';
import { fetchJson } from '../api';
import type { Finding } from '../types';
import { AttentionCard } from './AttentionCard';
import { ClosedList } from './ClosedList';

const TABS = [
  { key: 'attention', label: 'Needs attention' },
  { key: 'closed', label: 'Closed' },
] as const;

type Tab = (typeof TABS)[number]['key'];

interface ListProps {
  refreshKey: number;
  // Playbook entry id → title, for the entries an analysis relied on.
  entryTitles: ReadonlyMap<number, string>;
  onChanged: () => void;
}

export function FindingsSection({ refreshKey, entryTitles, onChanged }: ListProps) {
  const [tab, setTab] = useState<Tab>('attention');

  return (
    <div className="section">
      <div className="section-head">
        <h2 className="section-title">Findings</h2>
      </div>

      <div className="status-tabs">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            className={`status-tab${tab === t.key ? ' is-active' : ''}`}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'attention' ? (
        <AttentionList refreshKey={refreshKey} entryTitles={entryTitles} onChanged={onChanged} />
      ) : (
        <ClosedList refreshKey={refreshKey} entryTitles={entryTitles} onChanged={onChanged} />
      )}
    </div>
  );
}

function AttentionList({ refreshKey, entryTitles, onChanged }: ListProps) {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [failure, setFailure] = useState<{ id: number; message: string } | null>(null);

  // Server sorts the attention view by severity; triaging findings never appear here.
  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey/reloadKey drive a manual reload, not a data dependency
  useEffect(() => {
    fetchJson<Finding[]>('/api/findings?view=attention')
      .then((items) => {
        setFindings(items);
        setLoadError(null);
      })
      .catch((e) => setLoadError(String(e)));
  }, [refreshKey, reloadKey]);

  const orphanFailure = failure && !findings?.some((f) => f.id === failure.id) ? failure : null;

  return (
    <>
      {loadError && <p className="action-error">{loadError}</p>}
      {orphanFailure && <p className="action-error">Finding #{orphanFailure.id}: {orphanFailure.message}</p>}
      {!loadError && findings?.length === 0 && <p className="muted-line">Nothing needs your attention.</p>}
      <div className="findings-list">
        {findings?.map((f) => (
          <AttentionCard
            key={f.id}
            finding={f}
            entryTitles={entryTitles}
            error={failure?.id === f.id ? failure.message : null}
            onChanged={() => {
              setFailure(null);
              onChanged();
            }}
            onFailed={(message) => {
              setFailure({ id: f.id, message });
              setReloadKey((k) => k + 1);
            }}
            onClearError={() => setFailure((cur) => (cur?.id === f.id ? null : cur))}
          />
        ))}
      </div>
    </>
  );
}
