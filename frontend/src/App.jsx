import { useCallback, useEffect, useState } from 'react';
import { getMe, logout } from './api/auth.js';
import { deleteRepo, listRepos, triggerScan } from './api/repos.js';
import { EmptyState, ErrorState, Loading } from './components/StateMessage.jsx';
import LoginPage from './features/auth/LoginPage.jsx';
import AddRepoModal from './features/repos/AddRepoModal.jsx';
import FindingsTab from './features/findings/FindingsTab.jsx';
import FindingDetailDrawer from './features/findings/FindingDetailDrawer.jsx';
import SbomTab from './features/sbom/SbomTab.jsx';
import ScanHistoryTab from './features/scans/ScanHistoryTab.jsx';
import { formatDateTime } from './lib/format.js';
import { safeHttpUrl } from './lib/safeUrl.js';
import './App.css';

const TABS = [
  { id: 'findings', label: 'Findings' },
  { id: 'ignored', label: 'Ignored' },
  { id: 'sbom', label: 'SBOM' },
  { id: 'history', label: 'History' },
];

export default function App() {
  // Authentication state: "checking" -> "ready" (with user or null)
  const [authState, setAuthState] = useState({ status: 'checking', user: null });

  // Repository list and currently selected repository ID
  const [repoState, setRepoState] = useState({ status: 'idle', items: [], error: null });
  const [activeRepoId, setActiveRepoId] = useState(null);

  // Active tab, drawer state, add-repo modal, delete confirmation, and refresh trigger
  const [tab, setTab] = useState('findings');
  const [openFindingId, setOpenFindingId] = useState(null);
  const [showAddRepo, setShowAddRepo] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);
  const [busyAction, setBusyAction] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  // Restore existing session if an sb_token is saved in localStorage.
  useEffect(() => {
    let cancelled = false;
    getMe().then(
      (user) => !cancelled && setAuthState({ status: 'ready', user }),
      () => {
        logout();
        if (!cancelled) setAuthState({ status: 'ready', user: null });
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  const loadRepos = useCallback(() => {
    setRepoState((prev) => ({ status: 'loading', items: prev.items, error: null }));
    listRepos().then(
      (data) => {
        const items = data?.items || [];
        setRepoState({ status: 'ready', items, error: null });
        setActiveRepoId((prevId) => {
          if (prevId && items.some((r) => r.id === prevId)) return prevId;
          return items[0]?.id || null;
        });
      },
      (error) => setRepoState({ status: 'error', items: [], error }),
    );
  }, []);

  // Fetch the user's repositories as soon as they sign in.
  useEffect(() => {
    if (authState.user) {
      loadRepos();
    }
  }, [authState.user, loadRepos]);

  function handleSignOut() {
    logout();
    setAuthState({ status: 'ready', user: null });
    setRepoState({ status: 'idle', items: [], error: null });
    setActiveRepoId(null);
    setOpenFindingId(null);
    setConfirmDeleteId(null);
    setActionError(null);
  }

  function handleRepoAdded(newRepo) {
    setShowAddRepo(false);
    setRepoState((prev) => ({ status: 'ready', items: [newRepo, ...prev.items], error: null }));
    setActiveRepoId(newRepo.id);
    setTab('findings');
    setActionError(null);
  }

  async function handleDeleteRepo(repoId) {
    setBusyAction(true);
    setActionError(null);
    try {
      await deleteRepo(repoId);
      setConfirmDeleteId(null);
      setRepoState((prev) => {
        const remaining = prev.items.filter((r) => r.id !== repoId);
        setActiveRepoId((curr) => (curr === repoId ? remaining[0]?.id || null : curr));
        return { status: 'ready', items: remaining, error: null };
      });
    } catch (err) {
      setActionError(err?.message || 'Could not remove repository.');
    } finally {
      setBusyAction(false);
    }
  }

  async function handleRefresh() {
    if (!activeRepoId) return;
    setActionError(null);

    // Viewers only reload displayed data; analysts/admins trigger a new scan.
    if (canEdit) {
      setBusyAction(true);
      try {
        const scan = await triggerScan(activeRepoId);
        setRepoState((prev) => ({
          ...prev,
          items: prev.items.map((r) => (r.id === activeRepoId ? { ...r, lastScan: scan } : r)),
        }));
      } catch (err) {
        setActionError(err?.message || 'Scan trigger failed.');
      } finally {
        setBusyAction(false);
      }
    }
    setRefreshKey((k) => k + 1);
  }

  if (authState.status === 'checking') {
    return (
      <div className="boot-screen">
        <Loading label="Restoring session..." />
      </div>
    );
  }

  if (!authState.user) {
    return <LoginPage onAuthSuccess={(user) => setAuthState({ status: 'ready', user })} />;
  }

  const user = authState.user;
  const canEdit = user.role === 'admin' || user.role === 'analyst';
  const activeRepo = repoState.items.find((r) => r.id === activeRepoId) || null;
  const safeRepoUrl = activeRepo ? safeHttpUrl(activeRepo.url) : null;

  return (
    <div className="shell">
      <aside className="shell__sidebar" aria-label="Repositories">
        <div className="shell__brand">
          <span>SecureBuild</span>
          <span className="shell__role-pill">{user.role}</span>
        </div>

        <div className="shell__sidebar-head">
          <span className="shell__sidebar-label">Repositories</span>
          {canEdit && (
            <button
              type="button"
              className="btn btn--small btn--primary"
              onClick={() => setShowAddRepo(true)}
            >
              + Add
            </button>
          )}
        </div>

        {repoState.status === 'loading' && repoState.items.length === 0 ? (
          <p className="shell__sidebar-muted">Loading repos...</p>
        ) : repoState.items.length === 0 ? (
          <p className="shell__sidebar-muted">No repositories added yet.</p>
        ) : (
          <ul className="repo-list">
            {repoState.items.map((repo) => {
              const isActive = repo.id === activeRepoId;
              const isConfirming = confirmDeleteId === repo.id;
              return (
                <li key={repo.id} className="repo-list__item">
                  <button
                    type="button"
                    className={`shell__nav-item${isActive ? ' shell__nav-item--active' : ''}`}
                    aria-current={isActive ? 'page' : undefined}
                    onClick={() => {
                      setActiveRepoId(repo.id);
                      setConfirmDeleteId(null);
                      setOpenFindingId(null);
                    }}
                  >
                    <span className="repo-list__name">{repo.name}</span>
                    {repo.lastScan && (
                      <span className="repo-list__meta">
                        {repo.lastScan.findingsCount ?? 0} findings
                      </span>
                    )}
                  </button>

                  {canEdit && isActive && !isConfirming && (
                    <button
                      type="button"
                      className="repo-list__remove"
                      onClick={() => setConfirmDeleteId(repo.id)}
                      aria-label={`Remove ${repo.name}`}
                    >
                      Remove
                    </button>
                  )}

                  {canEdit && isConfirming && (
                    <div className="repo-confirm" role="group" aria-label={`Confirm removing ${repo.name}`}>
                      <span className="repo-confirm__text">Remove?</span>
                      <button
                        type="button"
                        className="btn btn--small btn--danger"
                        disabled={busyAction}
                        onClick={() => handleDeleteRepo(repo.id)}
                      >
                        Yes
                      </button>
                      <button
                        type="button"
                        className="btn btn--small"
                        disabled={busyAction}
                        onClick={() => setConfirmDeleteId(null)}
                      >
                        No
                      </button>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}

        <div className="shell__sidebar-foot">
          <div className="shell__user-name">{user.name}</div>
          <div className="shell__user-email">{user.email}</div>
          <button type="button" className="btn btn--small shell__signout" onClick={handleSignOut}>
            Sign out
          </button>
        </div>
      </aside>

      <div className="shell__main">
        <header className="shell__topbar">
          <div>
            <span className="muted">Repository</span>
            <h1 className="shell__repo">
              {activeRepo ? (
                safeRepoUrl ? (
                  <a href={safeRepoUrl} target="_blank" rel="noopener noreferrer" className="shell__repo-link">
                    {activeRepo.name}
                  </a>
                ) : (
                  activeRepo.name
                )
              ) : (
                'No repository selected'
              )}
            </h1>
            {activeRepo?.lastScan?.finishedAt && (
              <div className="muted shell__scan-meta">
                Last scan {formatDateTime(activeRepo.lastScan.finishedAt)}
                {activeRepo.lastScan.commitSha ? ` · ${activeRepo.lastScan.commitSha}` : ''}
              </div>
            )}
          </div>

          <div className="shell__actions">
            {activeRepo && (
              <button
                type="button"
                className="btn btn--primary"
                onClick={handleRefresh}
                disabled={busyAction}
              >
                {busyAction ? 'Scanning...' : 'Refresh'}
              </button>
            )}
          </div>
        </header>

        {actionError && (
          <div className="shell__banner" role="alert">
            {actionError}
          </div>
        )}

        {repoState.status === 'error' ? (
          <main className="shell__content">
            <div className="card">
              <ErrorState
                title="Could not load repositories"
                message={repoState.error?.message}
                onRetry={loadRepos}
              />
            </div>
          </main>
        ) : !activeRepo ? (
          <main className="shell__content">
            <div className="card">
              <EmptyState
                title="No repositories yet"
                message={
                  canEdit
                    ? 'Add a GitHub repository from the sidebar to scan dependencies and generate an SBOM.'
                    : 'Ask an analyst or administrator to add a repository.'
                }
              />
            </div>
          </main>
        ) : (
          <>
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
                {(tab === 'findings' || tab === 'ignored') && (
                  <FindingsTab
                    key={`${activeRepo.id}-${tab}`}
                    repoId={activeRepo.id}
                    statusFilter={tab === 'ignored' ? 'ignored' : 'open'}
                    refreshKey={refreshKey}
                    onOpenFinding={setOpenFindingId}
                  />
                )}
                {tab === 'sbom' && <SbomTab key={`${activeRepo.id}-${refreshKey}`} repoId={activeRepo.id} />}
                {tab === 'history' && (
                  <ScanHistoryTab key={activeRepo.id} repoId={activeRepo.id} refreshKey={refreshKey} />
                )}
              </div>
            </main>
          </>
        )}
      </div>

      {showAddRepo && (
        <AddRepoModal onClose={() => setShowAddRepo(false)} onAdded={handleRepoAdded} />
      )}

      {openFindingId && (
        <FindingDetailDrawer
          findingId={openFindingId}
          role={user.role}
          onClose={() => setOpenFindingId(null)}
          onChanged={() => setRefreshKey((k) => k + 1)}
        />
      )}
    </div>
  );
}
