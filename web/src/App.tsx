import { useEffect, useState } from 'react';
import { fetchJson } from './api';
import { AdminPage } from './components/AdminPage';
import { EventsOverTimeChart } from './components/EventsOverTimeChart';
import { FindingsSection } from './components/FindingsSection';
import { KpiStats } from './components/KpiStats';
import { PlaybookPage } from './components/PlaybookPage';
import { QueueStrip } from './components/QueueStrip';
import { SeverityChart } from './components/SeverityChart';
import { TopSignaturesChart } from './components/TopSignaturesChart';
import { TopSourceIpsChart } from './components/TopSourceIpsChart';
import { RefreshIcon, SettingsIcon, ShieldIcon } from './icons';
import type { Playbook, PlaybookProposal, QueueStats } from './types';

interface Health {
  status: 'ok' | 'degraded';
  sinkDb: 'available' | 'unavailable';
}

const RANGES = [
  { label: '24h', days: 1 },
  { label: '7d', days: 7 },
  { label: '30d', days: 30 },
];

export default function App() {
  if (window.location.pathname === '/admin') {
    return <AdminPage />;
  }
  if (window.location.pathname === '/playbook') {
    return <PlaybookPage />;
  }

  return <Dashboard />;
}

function Dashboard() {
  const [health, setHealth] = useState<Health | null>(null);
  const [sinceDays, setSinceDays] = useState(7);
  const [refreshKey, setRefreshKey] = useState(0);
  const [queue, setQueue] = useState<QueueStats | null>(null);
  const [pendingProposals, setPendingProposals] = useState(0);
  const [entryTitles, setEntryTitles] = useState<ReadonlyMap<number, string>>(new Map());
  const bumpRefresh = () => setRefreshKey((k) => k + 1);

  // Cards name the entries an analysis relied on; refetched on every refresh
  // so an added or retitled entry shows without a page reload.
  useEffect(() => {
    fetchJson<Playbook>('/api/playbook')
      .then(({ entries }) => setEntryTitles(new Map(entries.map((e) => [e.id, e.title]))))
      .catch(() => {});
  }, [refreshKey]);

  useEffect(() => {
    fetchJson<Health>('/health').then(setHealth).catch(() => setHealth(null));
    // Fetched once per refresh for both the KPI tile and the queue strip; a
    // failed refresh keeps the last good value rather than hiding the strip.
    fetchJson<QueueStats>('/api/queue')
      .then(setQueue)
      .catch(() => {});
    fetchJson<PlaybookProposal[]>('/api/playbook/proposals?status=pending')
      .then((rows) => setPendingProposals(rows.length))
      .catch(() => {});
  }, [refreshKey]);

  const sinkAvailable = health?.sinkDb === 'available';

  return (
    <>
      <div className="topbar">
        <div className="brand">
          <ShieldIcon size={28} />
          <div className="brand-text">
            <span className="brand-name">UniFi SIEM Lens</span>
            <span className="brand-sub">Security dashboard</span>
          </div>
        </div>
        <div className="topbar-right">
          <a className="nav-link" href="/playbook">
            Playbook
            {pendingProposals > 0 && (
              <span className="nav-badge" title={`${pendingProposals} pending proposals`}>
                {pendingProposals}
              </span>
            )}
          </a>
          <a className="icon-btn" href="/admin" aria-label="Admin">
            <SettingsIcon />
          </a>
          <div className={`status-pill${sinkAvailable ? '' : ' offline'}`}>
            <span className="status-dot" />
            {health === null ? 'Checking sink…' : sinkAvailable ? 'Sink connected' : 'Sink unavailable'}
          </div>
          <button className="icon-btn" type="button" aria-label="Refresh" onClick={bumpRefresh}>
            <RefreshIcon />
          </button>
        </div>
      </div>

      <div className="main">
        <div className="page-head">
          <div>
            <h1 className="page-title">Security overview</h1>
            <p className="page-subtitle">Heuristic findings and event trends across your UniFi network</p>
          </div>
          <div className="range-toggle">
            {RANGES.map((r) => (
              <button
                key={r.label}
                type="button"
                className={`range-opt${sinceDays === r.days ? ' active' : ''}`}
                onClick={() => setSinceDays(r.days)}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>

        <KpiStats refreshKey={refreshKey} queue={queue} />

        <div className="section">
          <div className="section-head">
            <h2 className="section-title">Trends</h2>
            <span className="section-count">last {sinceDays}d</span>
          </div>
          <div className="charts-grid-top">
            <EventsOverTimeChart sinceDays={sinceDays} />
          </div>
          <div className="charts-grid">
            <TopSignaturesChart sinceDays={sinceDays} />
            <TopSourceIpsChart sinceDays={sinceDays} />
            <SeverityChart sinceDays={sinceDays} />
          </div>
        </div>

        <div className="section">
          <QueueStrip refreshKey={refreshKey} queue={queue} />
          <FindingsSection refreshKey={refreshKey} entryTitles={entryTitles} onChanged={bumpRefresh} />
        </div>
      </div>

      <footer>
        <span className="footer-text">unifi-siem-lens · read-only analysis layer over unifi-siem-sink</span>
      </footer>
    </>
  );
}
