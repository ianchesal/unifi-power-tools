import { useEffect, useState } from 'react';
import { errorMessage, fetchJson, postJson } from '../api';
import { relativeTime } from '../format';
import { severityBand } from '../severity';
import type { Finding, HistoryEntry } from '../types';
import { EventsModal } from './EventsModal';
import { FindingIdentity } from './FindingIdentity';
import { HistoryTimeline } from './HistoryTimeline';
import { NoteBox } from './NoteBox';

const RISK_STYLE: Record<string, { bg: string; color: string }> = {
  low: { bg: 'var(--good-soft)', color: 'var(--good)' },
  medium: { bg: 'var(--warning-soft)', color: '#f7c860' },
  high: { bg: 'var(--critical-soft)', color: '#f28c88' },
};

function parseCitedEntries(raw: string | null): number[] {
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((n): n is number => typeof n === 'number') : [];
  } catch {
    return [];
  }
}

type CloseKind = 'handled' | 'not_concern';

// `error` is the message from this card's last failed action (owned by the
// list, so it survives the reload that follows a failure). `onFailed` reports
// one; `onChanged` is called after a successful action.
export function AttentionCard({
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
  const analysis = finding.latest_analysis;
  const hasRecommendation = analysis?.verdict === 'attention';
  const [closing, setClosing] = useState<CloseKind | null>(null);
  const [busy, setBusy] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [loaded, setLoaded] = useState<{ stamp: string; entries: HistoryEntry[] } | null>(null);
  const [historyError, setHistoryError] = useState(false);
  const [viewingEvents, setViewingEvents] = useState(false);

  // History loads on first expand — or on mount for fallback cards, which
  // need the latest human_reopened note for their headline.
  const needHistory = historyOpen || !hasRecommendation;
  // The cached timeline is only valid for the finding state it was loaded
  // for; a refresh that changes the finding refetches it.
  const historyStamp = `${finding.last_triaged_at}|${finding.last_activity_at}|${finding.reopen_count}`;
  const history = loaded?.stamp === historyStamp ? loaded.entries : null;
  useEffect(() => {
    if (!needHistory || history !== null) return;
    fetchJson<HistoryEntry[]>(`/api/findings/${finding.id}/history`)
      .then((entries) => {
        setLoaded({ stamp: historyStamp, entries });
        setHistoryError(false);
      })
      .catch(() => setHistoryError(true));
  }, [needHistory, history, historyStamp, finding.id]);

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await action();
      setClosing(null);
      onChanged();
    } catch (err) {
      onFailed(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const close = (kind: CloseKind, note: string) =>
    run(() => postJson(`/api/findings/${finding.id}/close`, note ? { kind, note } : { kind }));
  const reanalyze = () => run(() => postJson(`/api/findings/${finding.id}/reanalyze`));

  const reopenNote = history?.filter((h) => h.kind === 'human_reopened').at(-1)?.note ?? null;
  const cited = hasRecommendation ? parseCitedEntries(analysis.cited_entries) : [];
  const risk = analysis?.risk_level ?? null;

  return (
    <div className={`finding-card${severityBand(finding.severity_score) === 'crit' ? ' is-critical' : ''}`}>
      <FindingIdentity finding={finding} />

      {hasRecommendation ? (
        <div className="attention-body">
          <div className="analysis-head">
            <span
              className="analysis-badge"
              style={risk && RISK_STYLE[risk] ? { background: RISK_STYLE[risk].bg, color: RISK_STYLE[risk].color } : undefined}
            >
              Risk: {risk ?? 'unknown'}
            </span>
            {relativeTime(analysis.answered_at) && (
              <span className="analysis-source">via Claude Code · {relativeTime(analysis.answered_at)}</span>
            )}
          </div>
          <h3 className="attention-headline">{analysis.summary}</h3>
          {analysis.recommended_action && (
            <div className="recommended-action">
              <span className="recommended-action-label">Recommended action</span>
              <p className="analysis-body">{analysis.recommended_action}</p>
            </div>
          )}
          {(analysis.why_now || finding.reopen_count > 0) && (
            <p className="analysis-body">
              {finding.reopen_count > 0 && <span className="reopen-marker">Back after you closed it</span>}
              {analysis.why_now}
            </p>
          )}
          {cited.length > 0 && (
            <p className="muted-line">Cites playbook entries {cited.map((id) => `#${id}`).join(', ')}</p>
          )}
          {analysis.recommendation && (
            <details className="reasoning">
              <summary>Full reasoning</summary>
              <p className="analysis-body">{analysis.recommendation}</p>
            </details>
          )}
        </div>
      ) : (
        <div className="attention-body">
          <h3 className="attention-headline">Reopened — no AI recommendation yet</h3>
          {reopenNote && <p className="analysis-body">“{reopenNote}”</p>}
        </div>
      )}

      <div className="finding-actions">
        <button className="btn btn-ghost" type="button" disabled={busy} onClick={() => setClosing('handled')}>
          Handled
        </button>
        <button className="btn btn-ghost" type="button" disabled={busy} onClick={() => setClosing('not_concern')}>
          Not a concern
        </button>
        <button className="btn btn-ghost" type="button" onClick={() => setViewingEvents(true)}>
          View raw events
        </button>
        <span className="spacer" />
        {!hasRecommendation && (
          <button className="btn btn-primary" type="button" disabled={busy} onClick={reanalyze}>
            Re-analyze
          </button>
        )}
      </div>

      {closing && (
        <NoteBox
          key={closing}
          placeholder={closing === 'handled' ? 'What did you do?' : "Why isn't this a concern?"}
          busy={busy}
          onConfirm={(note) => close(closing, note)}
          onCancel={() => setClosing(null)}
        />
      )}

      {error && <p className="action-error">{error}</p>}

      <details className="history" onToggle={(e) => setHistoryOpen(e.currentTarget.open)}>
        <summary>History</summary>
        {historyError ? (
          <p className="muted-line">Couldn't load history.</p>
        ) : history === null ? (
          <p className="muted-line">Loading…</p>
        ) : (
          <HistoryTimeline entries={history} />
        )}
      </details>

      {viewingEvents && <EventsModal findingId={finding.id} onClose={() => setViewingEvents(false)} />}
    </div>
  );
}
