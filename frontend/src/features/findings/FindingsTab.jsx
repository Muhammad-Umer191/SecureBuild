import { useCallback, useEffect, useState } from 'react';
import { listFindings } from '../../api/findings.js';
import SeverityBadge from '../../components/SeverityBadge.jsx';
import { EmptyState, ErrorState, Loading } from '../../components/StateMessage.jsx';
import { formatDate } from '../../lib/format.js';
import useDebouncedValue from '../../lib/useDebouncedValue.js';
import './FindingsTab.css';

const PAGE_SIZE = 10;

const SEVERITY_CARDS = [
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
  { key: 'low', label: 'Low' },
];

const COLUMNS = [
  { key: 'vuln', label: 'Vulnerability' },
  { key: 'package', label: 'Package', sort: 'package' },
  { key: 'severity', label: 'Severity', sort: 'severity' },
  { key: 'fix', label: 'Recommended fix' },
  { key: 'published', label: 'Published', sort: 'published' },
];

/**
 * Filterable vulnerability findings table + severity summary cards.
 * Reused for both the "Findings" (open) and "Ignored" (ignored) tabs.
 * Props: repoId, statusFilter ('open' | 'ignored'), refreshKey, onOpenFinding(findingId)
 */
export default function FindingsTab({ repoId, statusFilter = 'open', refreshKey = 0, onOpenFinding }) {
  const [searchText, setSearchText] = useState('');
  const q = useDebouncedValue(searchText.trim(), 300);

  const [severity, setSeverity] = useState('');
  const [ecosystem, setEcosystem] = useState('');
  const [hasFix, setHasFix] = useState('');
  const [direct, setDirect] = useState('');
  const [sort, setSort] = useState('severity');
  const [order, setOrder] = useState('desc');
  const [page, setPage] = useState(1);

  const [state, setState] = useState({ status: 'loading', data: null, error: null });
  const [reloadKey, setReloadKey] = useState(0);

  // Reset to page 1 whenever the debounced search query changes.
  useEffect(() => {
    setPage(1);
  }, [q]);

  useEffect(() => {
    let cancelled = false;
    const params = {
      status: statusFilter,
      sort,
      order,
      page,
      limit: PAGE_SIZE,
    };
    if (q) params.q = q;
    if (severity) params.severity = severity;
    if (ecosystem) params.ecosystem = ecosystem;
    if (hasFix) params.hasFix = hasFix;
    if (direct) params.direct = direct;

    setState((prev) => ({
      ...prev,
      status: prev.data ? 'refreshing' : 'loading',
      error: null,
    }));

    listFindings(repoId, params).then(
      (data) => !cancelled && setState({ status: 'ready', data, error: null }),
      (error) => !cancelled && setState({ status: 'error', data: null, error }),
    );

    return () => {
      cancelled = true;
    };
  }, [repoId, statusFilter, q, severity, ecosystem, hasFix, direct, sort, order, page, refreshKey, reloadKey]);

  const retry = useCallback(() => setReloadKey((k) => k + 1), []);

  function changeFilter(setter) {
    return (e) => {
      setter(e.target.value);
      setPage(1);
    };
  }

  function toggleSeverityCard(key) {
    setSeverity((prev) => (prev === key ? '' : key));
    setPage(1);
  }

  function toggleSort(key) {
    if (sort === key) {
      setOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSort(key);
      setOrder(key === 'package' ? 'asc' : 'desc');
    }
    setPage(1);
  }

  function clearFilters() {
    setSearchText('');
    setSeverity('');
    setEcosystem('');
    setHasFix('');
    setDirect('');
    setPage(1);
  }

  const { status, data } = state;
  const filtersActive = Boolean(q || severity || ecosystem || hasFix || direct);
  const counts = data?.counts || { critical: 0, high: 0, medium: 0, low: 0, none: 0, unknown: 0 };
  const totalOpenOrIgnored =
    counts.critical + counts.high + counts.medium + counts.low + counts.none + counts.unknown;
  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.limit)) : 1;

  if (status === 'loading') {
    return (
      <div className="card">
        <Loading label="Loading findings..." />
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="card">
        <ErrorState title="Could not load findings" message={state.error?.message} onRetry={retry} />
      </div>
    );
  }

  return (
    <div className="findings">
      {/* Severity summary strip (clickable cards act as quick severity filters) */}
      <div className="findings__cards" role="list" aria-label="Findings severity summary">
        <div className="card findings__card" role="listitem">
          <div className="findings__card-value">{totalOpenOrIgnored}</div>
          <div className="muted">{statusFilter === 'ignored' ? 'Total ignored' : 'Total open'}</div>
        </div>

        {SEVERITY_CARDS.map((card) => {
          const active = severity === card.key;
          return (
            <button
              key={card.key}
              type="button"
              role="listitem"
              aria-pressed={active}
              className={`card findings__card findings__card--btn findings__card--${card.key}${
                active ? ' findings__card--selected' : ''
              }`}
              onClick={() => toggleSeverityCard(card.key)}
            >
              <div className="findings__card-value">{counts[card.key] ?? 0}</div>
              <div className="muted">{card.label}</div>
            </button>
          );
        })}
      </div>

      {/* Search and dropdown filters */}
      <div className="findings__filters" role="search">
        <div className="field">
          <label htmlFor="findings-search">Search</label>
          <input
            id="findings-search"
            type="search"
            placeholder="Package, GHSA, or CVE"
            maxLength={100}
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
          />
        </div>

        <div className="field">
          <label htmlFor="findings-severity">Severity</label>
          <select id="findings-severity" value={severity} onChange={changeFilter(setSeverity)}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="unknown">Unknown</option>
          </select>
        </div>

        <div className="field">
          <label htmlFor="findings-ecosystem">Ecosystem</label>
          <select id="findings-ecosystem" value={ecosystem} onChange={changeFilter(setEcosystem)}>
            <option value="">All ecosystems</option>
            <option value="npm">npm</option>
            <option value="PyPI">PyPI</option>
          </select>
        </div>

        <div className="field">
          <label htmlFor="findings-fix">Fix status</label>
          <select id="findings-fix" value={hasFix} onChange={changeFilter(setHasFix)}>
            <option value="">Any fix status</option>
            <option value="true">Fix available</option>
            <option value="false">No fix available</option>
          </select>
        </div>

        <div className="field">
          <label htmlFor="findings-direct">Dependency type</label>
          <select id="findings-direct" value={direct} onChange={changeFilter(setDirect)}>
            <option value="">Direct and transitive</option>
            <option value="true">Direct only</option>
            <option value="false">Transitive only</option>
          </select>
        </div>

        {filtersActive && (
          <button type="button" className="btn findings__reset" onClick={clearFilters}>
            Reset filters
          </button>
        )}
      </div>

      {/* Findings table */}
      <div className="card findings__tablecard" aria-busy={status === 'refreshing'}>
        {data.total === 0 ? (
          <div className="findings__empty">
            <EmptyState
              title={
                filtersActive
                  ? 'No findings match these filters'
                  : statusFilter === 'ignored'
                    ? 'No ignored findings'
                    : 'No open vulnerabilities found'
              }
              message={
                filtersActive
                  ? 'Try clearing one or more filters.'
                  : statusFilter === 'ignored'
                    ? 'Findings you ignore from the details drawer will appear here.'
                    : 'This repository currently has zero open findings.'
              }
            />
            {filtersActive && (
              <button type="button" className="btn" onClick={clearFilters}>
                Clear filters
              </button>
            )}
          </div>
        ) : (
          <div className="findings__scroll">
            <table className="findings__table">
              <caption className="sr-only">Repository vulnerability findings</caption>
              <thead>
                <tr>
                  {COLUMNS.map((col) => (
                    <th
                      key={col.key}
                      scope="col"
                      aria-sort={
                        col.sort && sort === col.sort
                          ? order === 'asc'
                            ? 'ascending'
                            : 'descending'
                          : undefined
                      }
                    >
                      {col.sort ? (
                        <button type="button" className="sort-btn" onClick={() => toggleSort(col.sort)}>
                          {col.label}
                          <span aria-hidden="true">
                            {sort === col.sort ? (order === 'asc' ? ' ▲' : ' ▼') : ''}
                          </span>
                        </button>
                      ) : (
                        col.label
                      )}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.items.map((f) => (
                  <tr key={f.id} className="findings__row" onClick={() => onOpenFinding(f.id)}>
                    <td>
                      <button
                        type="button"
                        className="link-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          onOpenFinding(f.id);
                        }}
                      >
                        {f.vulnId}
                      </button>
                      <div className="muted findings__summary">{f.summary}</div>
                      {f.cveIds?.length > 0 && (
                        <div className="findings__cves mono">{f.cveIds.join(', ')}</div>
                      )}
                    </td>
                    <td>
                      <div className="mono">{f.package.name}@{f.package.version}</div>
                      <div className="muted findings__pkg-meta">
                        {f.package.ecosystem} · {f.direct ? 'Direct' : 'Transitive'}
                      </div>
                    </td>
                    <td>
                      <SeverityBadge severity={f.severity} score={f.score} />
                    </td>
                    <td>
                      {f.hasFix && f.recommendedFix ? (
                        <span className="findings__fix mono">{f.recommendedFix}</span>
                      ) : (
                        <span className="muted">No fix</span>
                      )}
                    </td>
                    <td className="muted">{formatDate(f.published)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {data.total > 0 && (
          <nav className="findings__pager" aria-label="Findings pagination">
            <span className="muted">
              {(data.page - 1) * data.limit + 1}-{Math.min(data.page * data.limit, data.total)} of {data.total}
            </span>
            <div className="findings__pager-btns">
              <button
                type="button"
                className="btn btn--small"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </button>
              <span aria-live="polite">
                Page {data.page} of {totalPages}
              </span>
              <button
                type="button"
                className="btn btn--small"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </button>
            </div>
          </nav>
        )}
      </div>
    </div>
  );
}
