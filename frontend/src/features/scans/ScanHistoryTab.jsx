import { useCallback, useEffect, useState } from 'react';
import { listScans } from '../../api/scans.js';
import { EmptyState, ErrorState, Loading } from '../../components/StateMessage.jsx';
import { formatDateTime } from '../../lib/format.js';
import './ScanHistoryTab.css';

const STATUS_LABELS = {
  completed: 'Completed',
  failed: 'Failed',
  running: 'Running',
  queued: 'Queued',
};

/**
 * Displays past scan runs for the currently selected repository.
 * Props: repoId, refreshKey
 */
export default function ScanHistoryTab({ repoId, refreshKey = 0 }) {
  const [state, setState] = useState({ status: 'loading', items: [], error: null });
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setState((prev) => ({
      status: prev.items.length > 0 ? 'refreshing' : 'loading',
      items: prev.items,
      error: null,
    }));

    listScans(repoId).then(
      (data) => !cancelled && setState({ status: 'ready', items: data?.items || [], error: null }),
      (error) => !cancelled && setState({ status: 'error', items: [], error }),
    );

    return () => {
      cancelled = true;
    };
  }, [repoId, refreshKey, reloadKey]);

  const retry = useCallback(() => setReloadKey((k) => k + 1), []);

  if (state.status === 'loading') {
    return (
      <div className="card">
        <Loading label="Loading scan history..." />
      </div>
    );
  }

  if (state.status === 'error') {
    return (
      <div className="card">
        <ErrorState
          title="Could not load scan history"
          message={state.error?.message}
          onRetry={retry}
        />
      </div>
    );
  }

  if (state.items.length === 0) {
    return (
      <div className="card">
        <EmptyState
          title="No scans recorded yet"
          message="Click Refresh in the top bar to trigger the first scan for this repository."
        />
      </div>
    );
  }

  return (
    <div className="scans">
      <div className="scans__header">
        <div>
          <h2 className="scans__title">Scan history</h2>
          <p className="muted scans__subtitle">
            {state.items.length} recorded {state.items.length === 1 ? 'run' : 'runs'} for this repository
          </p>
        </div>
      </div>

      <div className="card scans__tablecard" aria-busy={state.status === 'refreshing'}>
        <div className="scans__scroll">
          <table className="scans__table">
            <caption className="sr-only">Repository scan runs</caption>
            <thead>
              <tr>
                <th scope="col">Status</th>
                <th scope="col">Commit</th>
                <th scope="col">Started</th>
                <th scope="col">Finished</th>
                <th scope="col">Findings</th>
                <th scope="col">Components</th>
                <th scope="col">Notes</th>
              </tr>
            </thead>
            <tbody>
              {state.items.map((scan) => {
                const statusKey = STATUS_LABELS[scan.status] ? scan.status : 'queued';
                return (
                  <tr key={scan.id}>
                    <td>
                      <span className={`scan-badge scan-badge--${statusKey}`}>
                        {STATUS_LABELS[statusKey]}
                      </span>
                    </td>
                    <td className="mono">{scan.commitSha || '-'}</td>
                    <td className="muted">{formatDateTime(scan.startedAt)}</td>
                    <td className="muted">{formatDateTime(scan.finishedAt)}</td>
                    <td>{scan.findingsCount ?? 0}</td>
                    <td>{scan.componentsCount ?? 0}</td>
                    <td>
                      {scan.error ? (
                        <span className="scans__error">{scan.error}</span>
                      ) : (
                        <span className="muted">Completed cleanly</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
