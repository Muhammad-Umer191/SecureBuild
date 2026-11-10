// DEMO HARNESS ONLY. This shell (sidebar, top bar, tabs, the simple findings list and the role
// switcher) exists so F2's two pieces can be shown on their own: <FindingDetailDrawer /> and <SbomTab />.
// F1 owns the real application layout and the real filterable findings table; drop the two
// components into that instead of using this file.
import { useEffect, useState } from 'react';
import { listFindings } from './api/findings.js';
import SeverityBadge from './components/SeverityBadge.jsx';
import { Loading, ErrorState, EmptyState } from './components/StateMessage.jsx';
import FindingDetailDrawer from './features/findings/FindingDetailDrawer.jsx';
import SbomTab from './features/sbom/SbomTab.jsx';
import './App.css';

// Point the harness at a real repo with VITE_DEMO_REPO_ID (printed by `npm run demo` in backend/).
const REPO_ID = import.meta.env.VITE_DEMO_REPO_ID || '6650a1b2c3d4e5f600000000';
const REPO_NAME = 'acme/demo-repo';
const TABS = [
  { id: 'findings', label: 'Findings' },
  { id: 'sbom', label: 'SBOM' },
];

export default function App() {
  const [tab, setTab] = useState('findings');
  const [role, setRole] = useState('analyst');
  const [openId, setOpenId] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  return (
    <div className="shell">
      <nav className="shell__sidebar" aria-label="Main">
        <div className="shell__brand">SecureBuild</div>
        <ul>
          <li className="shell__nav-item shell__nav-item--active" aria-current="page">Repositories</li>
          <li className="shell__nav-item">Scans</li>
          <li className="shell__nav-item">Settings</li>
        </ul>
      </nav>
      <div className="shell__main">
        <header className="shell__topbar">
          <div>
            <span className="muted">Repository</span>
            <h1 className="shell__repo">{REPO_NAME}</h1>
          </div>
          <div className="shell__actions">
            <label className="shell__role">
              Demo role
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="admin">admin</option>
                <option value="analyst">analyst</option>
                <option value="viewer">viewer</option>
              </select>
            </label>
            {/* Placeholder: the real refresh/rescan action belongs to the frontend lead. */}
            <button type="button" className="btn btn--primary" onClick={() => setRefreshKey((k) => k + 1)}>
              Refresh
            </button>
          </div>
        </header>

        <div className="shell__tabs" role="tablist" aria-label="Repository views">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={tab === t.id}
              aria-controls={`panel-${t.id}`}
              className={`shell__tab${tab === t.id ? ' shell__tab--active' : ''}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>

        <main className="shell__content">
          <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
            {tab === 'findings' ? (
              <SimpleFindingsList refreshKey={refreshKey} onOpen={setOpenId} />
            ) : (
              <SbomTab key={refreshKey} repoId={REPO_ID} />
            )}
          </div>
        </main>
      </div>

      {openId && (
        <FindingDetailDrawer
          findingId={openId}
          role={role}
          onClose={() => setOpenId(null)}
          onChanged={() => setRefreshKey((k) => k + 1)}
        />
      )}
    </div>
  );
}

function SimpleFindingsList({ refreshKey, onOpen }) {
  const [state, setState] = useState({ status: 'loading', data: null, error: null });

  useEffect(() => {
    let cancelled = false;
    listFindings(REPO_ID, { status: 'all', limit: 100 }).then(
      (data) => !cancelled && setState({ status: 'ready', data, error: null }),
      (error) => !cancelled && setState({ status: 'error', data: null, error }),
    );
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  if (state.status === 'loading') return <Loading label="Loading findings..." />;
  if (state.status === 'error') return <ErrorState message={state.error?.message} />;
  if (state.data.items.length === 0) return <EmptyState title="No findings" />;

  return (
    <div className="card">
      <table className="harness-table">
        <caption className="sr-only">Findings (demo list, click a row to open details)</caption>
        <thead>
          <tr>
            <th scope="col">Vulnerability</th>
            <th scope="col">Package</th>
            <th scope="col">Severity</th>
            <th scope="col">Status</th>
          </tr>
        </thead>
        <tbody>
          {state.data.items.map((f) => (
            <tr key={f.id} className="harness-row" onClick={() => onOpen(f.id)}>
              <td>
                <button
                  type="button"
                  className="link-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    onOpen(f.id);
                  }}
                >
                  {f.vulnId}
                </button>
                <div className="muted">{f.summary}</div>
              </td>
              <td className="mono">{f.package.name}@{f.package.version}</td>
              <td><SeverityBadge severity={f.severity} score={f.score} /></td>
              <td>{f.status === 'ignored' ? 'Ignored' : 'Open'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
