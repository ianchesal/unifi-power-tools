import { useEffect, useState } from 'react';
import { fetchJson } from '../api';
import { relativeTime } from '../format';
import type { Finding, PendingAnalysis, QueueStats } from '../types';

// Phase B swaps this for the slash command.
export const TRIAGE_HINT = 'ask Claude Code to work the unifi-siem-lens analysis queue';

// `queue` is fetched once per refresh by the parent (shared with KpiStats),
// which keeps the last good value on a failed refresh.
export function QueueStrip({ refreshKey, queue }: { refreshKey: number; queue: QueueStats | null }) {
  const [expanded, setExpanded] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [recheckIds, setRecheckIds] = useState<Set<number>>(new Set());
  const [listError, setListError] = useState(false);

  // Item details load only while expanded: two calls total, never per item.
  useEffect(() => {
    if (!expanded) return;
    Promise.all([
      fetchJson<Finding[]>('/api/findings?view=triaging'),
      fetchJson<PendingAnalysis[]>('/api/analysis-requests'),
    ])
      .then(([f, pending]) => {
        setFindings(f);
        setRecheckIds(new Set(pending.filter((p) => p.is_recheck === 1).map((p) => p.finding_id)));
        setListError(false);
      })
      .catch(() => {
        setFindings([]);
        setRecheckIds(new Set());
        setListError(true);
      });
  }, [expanded, refreshKey]);

  if (!queue) return null;

  if (queue.count === 0) {
    const last = relativeTime(queue.last_answered_at);
    return (
      <div className="queue-strip">
        <span>{last ? `Queue empty · last AI analysis ${last}` : 'Queue empty · no AI analysis yet'}</span>
      </div>
    );
  }

  const oldest = relativeTime(queue.oldest_created_at);
  return (
    <div className="queue-strip">
      <button type="button" className="queue-strip-toggle" aria-expanded={expanded} onClick={() => setExpanded((v) => !v)}>
        {queue.count} finding{queue.count === 1 ? '' : 's'} waiting for AI analysis
        {oldest ? ` · oldest ${oldest}` : ''} · {TRIAGE_HINT}
      </button>
      {expanded && listError && <p className="queue-strip-error">Couldn't load the queued findings.</p>}
      {expanded && !listError && (
        <ul className="queue-strip-list">
          {findings.map((f) => (
            <li key={f.id}>
              <span className="mono">{f.display_name ?? f.entity_key}</span>
              <span className="queue-strip-meta">
                {f.entity_type} · priority {f.severity_score}
              </span>
              {recheckIds.has(f.id) && <span className="queue-strip-tag">recheck</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
