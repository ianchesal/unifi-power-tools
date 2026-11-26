import { useEffect, useState } from 'react';
import { fetchJson } from '../api';
import { relativeTime } from '../format';
import type { Finding, HistoryEntry } from '../types';

export function HistoryTimeline({ entries }: { entries: HistoryEntry[] }) {
  if (entries.length === 0) return <p className="muted-line">No history yet.</p>;
  return (
    <ol className="history-timeline">
      {entries.map((e) => (
        <li key={e.id}>
          <span className="timestamp">{relativeTime(e.at) ?? e.at}</span>
          <span className={`history-actor ${e.actor}`}>{e.actor}</span>
          <span className="history-summary">
            {e.summary}
            {e.note && <span className="history-note"> “{e.note}”</span>}
          </span>
        </li>
      ))}
    </ol>
  );
}

// A collapsed "History" section that fetches the finding's timeline on first
// expand only, so rendering a list of cards makes no per-card calls.
export function HistoryDetails({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const [loaded, setLoaded] = useState<{ stamp: string; entries: HistoryEntry[] } | null>(null);
  const [failed, setFailed] = useState(false);

  // The cached timeline is only valid for the finding state it was loaded
  // for; a refresh that changes the finding refetches it (when expanded).
  const stamp = `${finding.status}|${finding.last_triaged_at}|${finding.last_activity_at}|${finding.reopen_count}`;
  const entries = loaded?.stamp === stamp ? loaded.entries : null;
  useEffect(() => {
    if (!open || entries !== null) return;
    fetchJson<HistoryEntry[]>(`/api/findings/${finding.id}/history`)
      .then((rows) => {
        setLoaded({ stamp, entries: rows });
        setFailed(false);
      })
      .catch(() => setFailed(true));
  }, [open, entries, stamp, finding.id]);

  return (
    <details className="history" onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary>History</summary>
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
