import { useCallback, useEffect, useState } from 'react';
import { listComponents, exportSbom } from '../../api/components.js';
import SeverityBadge from '../../components/SeverityBadge.jsx';
import { Loading, ErrorState, EmptyState } from '../../components/StateMessage.jsx';
import useDebouncedValue from '../../lib/useDebouncedValue.js';
import { downloadBlob } from '../../lib/download.js';
import { formatDateTime } from '../../lib/format.js';
import './SbomTab.css';

const PAGE_SIZE = 20;
const COLUMNS = [
  { key: 'name', label: 'Name', sort: 'name' },
  { key: 'version', label: 'Version' },
  { key: 'ecosystem', label: 'Ecosystem', sort: 'ecosystem' },
  { key: 'direct', label: 'Type' },
  { key: 'licenses', label: 'Licenses' },
  { key: 'vulns', label: 'Vulnerabilities', sort: 'vulns' },
  { key: 'purl', label: 'purl' },
];

/**
 * SBOM tab: every component in the latest scan of a repo.
 * Props: repoId (string), scanId? (optional, defaults to the latest scan)
 */
export default function SbomTab({ repoId, scanId }) {
  const [searchText, setSearchText] = useState('');
  const q = useDebouncedValue(searchText.trim(), 300);
  const [ecosystem, setEcosystem] = useState('');
  const [direct, setDirect] = useState('');
  const [vulnerableOnly, setVulnerableOnly] = useState(false);
  const [sort, setSort] = useState('name');
  const [order, setOrder] = useState('asc');
  const [page, setPage] = useState(1);

  const [state, setState] = useState({ status: 'loading', data: null, error: null });
  const [reloadKey, setReloadKey] = useState(0);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState(null);

  // Reset to page 1 whenever the debounced search text changes.
  useEffect(() => setPage(1), [q]);

  useEffect(() => {
    let cancelled = false;
    const params = { sort, order, page, limit: PAGE_SIZE };
    if (scanId) params.scanId = scanId;
    if (q) params.q = q;
    if (ecosystem) params.ecosystem = ecosystem;
    if (direct) params.direct = direct;
    if (vulnerableOnly) params.vulnerable = 'true';

    setState((s) => ({ ...s, status: s.data ? 'refreshing' : 'loading', error: null }));
    listComponents(repoId, params).then(
      (data) => !cancelled && setState({ status: 'ready', data, error: null }),
      (error) =>
        !cancelled &&
        setState({ status: error?.code === 'NO_SCAN' ? 'noscan' : 'error', data: null, error }),
    );
    return () => {
      cancelled = true;
    };
  }, [repoId, scanId, q, ecosystem, direct, vulnerableOnly, sort, order, page, reloadKey]);

  const retry = useCallback(() => setReloadKey((k) => k + 1), []);

  function changeFilter(setter) {
    return (e) => {
      setter(e.target.value);
      setPage(1);
    };
  }

  function toggleSort(key) {
    if (sort === key) setOrder((o) => (o === 'asc' ? 'desc' : 'asc'));
    else {
      setSort(key);
      setOrder(key === 'vulns' ? 'desc' : 'asc');
    }
    setPage(1);
  }

  function clearFilters() {
    setSearchText('');
    setEcosystem('');
    setDirect('');
    setVulnerableOnly(false);
    setPage(1);
  }

  async function onExport() {
    setExporting(true);
    setExportError(null);
    try {
      const { blob, filename } = await exportSbom(repoId, scanId ? { scanId } : undefined);
      downloadBlob(blob, filename || 'sbom.cdx.json');
    } catch (e) {
      setExportError(e?.message || 'Export failed.');
    } finally {
      setExporting(false);
    }
  }

  const { status, data } = state;
  const filtersActive = Boolean(q || ecosystem || direct || vulnerableOnly);
  const ecosystems = data ? Object.keys(data.summary.byEcosystem) : [];
  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.limit)) : 1;

  return (
    <div className="sbom">
      <div className="sbom__toolbar">
        <div>
          <h2 className="sbom__title">Software bill of materials</h2>
          {data?.scan && (
            <p className="muted sbom__scan">
              Latest scan {data.scan.commitSha ? <code>{data.scan.commitSha}</code> : null}
              {data.scan.finishedAt ? ` finished ${formatDateTime(data.scan.finishedAt)}` : ''}
            </p>
          )}
        </div>
        <button type="button" className="btn btn--primary" onClick={onExport} disabled={exporting || status === 'noscan'}>
          {exporting ? 'Exporting...' : 'Export CycloneDX'}
        </button>
      </div>
      {exportError && <p role="alert" className="field-error">{exportError}</p>}

      {status === 'noscan' && (
        <div className="card">
          <EmptyState title="No completed scan yet" message="Run a scan on this repository to generate its SBOM." />
        </div>
      )}
      {status === 'error' && (
        <div className="card">
          <ErrorState title="Could not load the SBOM" message={state.error?.message} onRetry={retry} />
        </div>
      )}
      {status === 'loading' && (
        <div className="card">
          <Loading label="Loading components..." />
        </div>
      )}

      {data && (status === 'ready' || status === 'refreshing') && (
        <>
          <div className="sbom__cards" role="list" aria-label="SBOM summary">
            <SummaryCard label="Total components" value={data.summary.total} />
            <SummaryCard label="Direct" value={data.summary.direct} />
            <SummaryCard label="Transitive" value={data.summary.transitive} />
            <SummaryCard label="Vulnerable" value={data.summary.vulnerable} emphasis={data.summary.vulnerable > 0} />
            {ecosystems.map((eco) => (
              <SummaryCard key={eco} label={`${eco} packages`} value={data.summary.byEcosystem[eco]} />
            ))}
          </div>

          <div className="sbom__filters" role="search">
            <div className="field">
              <label htmlFor="sbom-search">Search</label>
              <input
                id="sbom-search"
                type="search"
                placeholder="Name or purl"
                maxLength={100}
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="sbom-eco">Ecosystem</label>
              <select id="sbom-eco" value={ecosystem} onChange={changeFilter(setEcosystem)}>
                <option value="">All ecosystems</option>
                <option value="npm">npm</option>
                <option value="PyPI">PyPI</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="sbom-direct">Dependency type</label>
              <select id="sbom-direct" value={direct} onChange={changeFilter(setDirect)}>
                <option value="">Direct and transitive</option>
                <option value="true">Direct only</option>
                <option value="false">Transitive only</option>
              </select>
            </div>
            <label className="field field--check" htmlFor="sbom-vuln">
              <input
                id="sbom-vuln"
                type="checkbox"
                checked={vulnerableOnly}
                onChange={(e) => {
                  setVulnerableOnly(e.target.checked);
                  setPage(1);
                }}
              />
              Vulnerable only
            </label>
          </div>

          <div className="card sbom__tablecard" aria-busy={status === 'refreshing'}>
            {data.total === 0 ? (
              <EmptyState
                title={filtersActive ? 'No components match these filters' : 'No components in this scan'}
                message={filtersActive ? undefined : 'The lockfiles in this scan did not list any packages.'}
              />
            ) : (
              <div className="sbom__scroll">
                <table className="sbom__table">
                  <caption className="sr-only">Components found in the latest scan</caption>
                  <thead>
                    <tr>
                      {COLUMNS.map((c) => (
                        <th
                          key={c.key}
                          scope="col"
                          aria-sort={c.sort && sort === c.sort ? (order === 'asc' ? 'ascending' : 'descending') : undefined}
                        >
                          {c.sort ? (
                            <button type="button" className="sort-btn" onClick={() => toggleSort(c.sort)}>
                              {c.label}
                              <span aria-hidden="true" className="sort-btn__arrow">
                                {sort === c.sort ? (order === 'asc' ? ' ▲' : ' ▼') : ''}
                              </span>
                            </button>
                          ) : (
                            c.label
                          )}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((c) => (
                      <tr key={c.id}>
                        <th scope="row" className="sbom__name">{c.name}</th>
                        <td className="mono">{c.version}</td>
                        <td>{c.ecosystem}</td>
                        <td>{c.direct ? 'Direct' : 'Transitive'}</td>
                        <td>{c.licenses?.length ? c.licenses.join(', ') : <span className="muted">Unknown</span>}</td>
                        <td>
                          {c.vulnerabilityCount > 0 ? (
                            <span className="sbom__vulns">
                              {c.vulnerabilityCount}
                              <SeverityBadge severity={c.maxSeverity || 'unknown'} />
                            </span>
                          ) : (
                            <span className="muted">0</span>
                          )}
                        </td>
                        <td className="mono sbom__purl">{c.purl}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {data.total > 0 && (
              <nav className="sbom__pager" aria-label="Pagination">
                <span className="muted">
                  {(data.page - 1) * data.limit + 1}-{Math.min(data.page * data.limit, data.total)} of {data.total}
                </span>
                <div className="btn-row">
                  <button type="button" className="btn btn--small" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                    Previous
                  </button>
                  <span aria-live="polite">Page {data.page} of {totalPages}</span>
                  <button type="button" className="btn btn--small" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                    Next
                  </button>
                </div>
              </nav>
            )}
            {filtersActive && data.total === 0 && (
              <div className="sbom__clear">
                <button type="button" className="btn" onClick={clearFilters}>Clear filters</button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function SummaryCard({ label, value, emphasis }) {
  return (
    <div className={`card sbom__card${emphasis ? ' sbom__card--alert' : ''}`} role="listitem">
      <div className="sbom__card-value">{value}</div>
      <div className="muted">{label}</div>
    </div>
  );
}
