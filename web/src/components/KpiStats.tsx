import { useEffect, useState } from 'react';
import { fetchJson } from '../api';
import { relativeTime } from '../format';
import type { FindingsSummary, QueueStats } from '../types';

interface EventsRow {
  day: string;
  category: string;
  count: number;
}

export function KpiStats({ refreshKey, queue }: { refreshKey: number; queue: QueueStats | null }) {
  const [summary, setSummary] = useState<FindingsSummary | null>(null);
  const [eventRows, setEventRows] = useState<EventsRow[] | null>(null);

  useEffect(() => {
    fetchJson<FindingsSummary>('/api/findings-summary').then(setSummary).catch(() => setSummary(null));
  }, [refreshKey]);

  useEffect(() => {
    fetchJson<EventsRow[]>('/api/stats/activity-over-time?sinceDays=2')
      .then(setEventRows)
      .catch(() => setEventRows(null));
  }, [refreshKey]);

  const attention = summary?.attention ?? null;
  const closed = summary?.closed_last_7d ?? null;
  const closedTotal = closed ? closed.rule + closed.ai + closed.human + closed.system : null;
  const oldestAge = relativeTime(queue?.oldest_created_at);

  let last24h: number | null = null;
  let priorDayDeltaPct: number | null = null;
  if (eventRows) {
    const byDay = new Map<string, number>();
    for (const r of eventRows) byDay.set(r.day, (byDay.get(r.day) ?? 0) + r.count);
    const days = [...byDay.keys()].sort();
    const today = days.at(-1);
    const yesterday = days.at(-2);
    if (today !== undefined) last24h = byDay.get(today) ?? 0;
    if (today !== undefined && yesterday !== undefined) {
      const prior = byDay.get(yesterday) ?? 0;
      if (prior > 0 && last24h !== null) {
        priorDayDeltaPct = Math.round(((last24h - prior) / prior) * 100);
      }
    }
  }

  return (
    <div className="kpi-grid">
      <KpiCard
        label="Needs attention"
        value={attention}
        iconBg="var(--critical-soft)"
        iconColor="#f28c88"
        icon={
          <>
            <path d="M12 3 2 20h20L12 3Z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
            <path d="M12 10v4M12 17h.01" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
          </>
        }
        delta={attention !== null && attention > 0 ? 'needs review' : undefined}
        deltaClass={attention !== null && attention > 0 ? 'up' : undefined}
      />
      <KpiCard
        label="AI queue"
        value={queue?.count ?? null}
        iconBg="var(--accent-soft)"
        iconColor="#7fb2ee"
        icon={<path d="M4 5h16M4 12h16M4 19h10" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />}
        delta={queue && queue.count > 0 && oldestAge ? `oldest ${oldestAge}` : undefined}
      />
      <KpiCard
        label="Closed, 7d"
        value={closedTotal}
        iconBg="var(--good-soft)"
        iconColor="var(--good)"
        icon={<path d="m5 12 5 5 9-10" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />}
        delta={closed ? `rule ${closed.rule} · AI ${closed.ai} · human ${closed.human}` : undefined}
      />
      <KpiCard
        label="Events, 24h"
        value={last24h}
        mono
        iconBg="var(--surface-3)"
        iconColor="var(--text-secondary)"
        icon={<path d="M3 17 9 9l4 4 8-10" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />}
        delta={priorDayDeltaPct !== null ? `${priorDayDeltaPct > 0 ? '+' : ''}${priorDayDeltaPct}% vs prior day` : undefined}
        deltaClass={priorDayDeltaPct !== null ? (priorDayDeltaPct > 0 ? 'up' : 'down') : undefined}
      />
    </div>
  );
}

function KpiCard({
  label,
  value,
  icon,
  iconBg,
  iconColor,
  mono,
  delta,
  deltaClass,
}: {
  label: string;
  value: number | null;
  icon: React.ReactNode;
  iconBg: string;
  iconColor: string;
  mono?: boolean;
  delta?: string;
  deltaClass?: 'up' | 'down';
}) {
  return (
    <div className="kpi-card">
      <div className="kpi-top">
        <span className="kpi-label">{label}</span>
        <div className="kpi-icon" style={{ background: iconBg, color: iconColor }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
            {icon}
          </svg>
        </div>
      </div>
      <span className={`kpi-value${mono ? ' mono' : ''}`}>{value === null ? '—' : value.toLocaleString()}</span>
      {delta && <span className={`kpi-delta${deltaClass ? ` ${deltaClass}` : ''}`}>{delta}</span>}
    </div>
  );
}
