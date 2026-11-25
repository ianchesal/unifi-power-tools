import { relativeTime } from '../format';
import type { HistoryEntry } from '../types';

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
