import { useState } from 'react';
import { errorMessage, postJson } from '../api';
import { relativeTime } from '../format';
import { severityBand } from '../severity';
import type { Finding } from '../types';
import { EventsModal } from './EventsModal';
import { FindingIdentity } from './FindingIdentity';
import { HistoryDetails } from './HistoryTimeline';
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
// one; `onClearError` drops it when the operator cancels or starts a new
// action; `onChanged` is called after a successful action.
export function AttentionCard({
  finding,
  error,
  onChanged,
  onFailed,
  onClearError,
}: {
  finding: Finding;
  error: string | null;
  onChanged: () => void;
  onFailed: (message: string) => void;
  onClearError: () => void;
}) {
  const analysis = finding.latest_analysis;
  // An AI verdict stamps last_triaged_at and answered_at with the same time, so
  // a later last_triaged_at means a human decided after it (e.g. Handled, then
  // This was wrong): the old recommendation is stale, so show the fallback.
  const humanDecidedAfter =
    analysis?.answered_at != null &&
    finding.last_triaged_at != null &&
    finding.last_triaged_at > analysis.answered_at;
  const hasRecommendation = analysis?.verdict === 'attention' && !humanDecidedAfter;
  const [closing, setClosing] = useState<CloseKind | null>(null);
  const [busy, setBusy] = useState(false);
  const [viewingEvents, setViewingEvents] = useState(false);

  const openNote = (kind: CloseKind) => {
    onClearError();
    setClosing(kind);
  };
  const cancelNote = () => {
    onClearError();
    setClosing(null);
  };

  const run = async (action: () => Promise<unknown>) => {
    onClearError();
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

  const reopenNote = finding.latest_reopen_note;
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
        <button className="btn btn-ghost" type="button" disabled={busy} onClick={() => openNote('handled')}>
          Handled
        </button>
        <button className="btn btn-ghost" type="button" disabled={busy} onClick={() => openNote('not_concern')}>
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
          onCancel={cancelNote}
        />
      )}

      {error && <p className="action-error">{error}</p>}

      <HistoryDetails finding={finding} />

      {viewingEvents && <EventsModal findingId={finding.id} onClose={() => setViewingEvents(false)} />}
    </div>
  );
}
