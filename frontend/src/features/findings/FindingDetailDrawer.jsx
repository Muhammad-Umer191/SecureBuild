import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { getFinding, updateFinding } from '../../api/findings.js';
import SeverityBadge from '../../components/SeverityBadge.jsx';
import CopyButton from '../../components/CopyButton.jsx';
import { Loading, ErrorState } from '../../components/StateMessage.jsx';
import { parseCvssVector } from '../../lib/cvss.js';
import { upgradeCommands } from '../../lib/upgradeCommand.js';
import { safeHttpUrl } from '../../lib/safeUrl.js';
import { formatDate, formatDateTime } from '../../lib/format.js';
import './FindingDetailDrawer.css';

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

export const REASON_MIN = 5;
export const REASON_MAX = 500;

export function validateReason(raw) {
  const len = raw.trim().length;
  if (len < REASON_MIN) return `Please enter at least ${REASON_MIN} characters.`;
  if (len > REASON_MAX) return `Please keep the reason under ${REASON_MAX} characters (currently ${len}).`;
  return null;
}

/**
 * Right-side slide-over with everything about one finding.
 * Props: findingId, role ('admin' | 'analyst' | 'viewer'), onClose(), onChanged?(updatedFinding)
 */
export default function FindingDetailDrawer({ findingId, role, onClose, onChanged }) {
  const titleId = useId();
  const panelRef = useRef(null);
  const closeRef = useRef(null);
  const openerRef = useRef(typeof document !== 'undefined' ? document.activeElement : null);
  const [state, setState] = useState({ status: 'loading', finding: null, error: null });

  const load = useCallback(() => {
    let cancelled = false;
    setState({ status: 'loading', finding: null, error: null });
    getFinding(findingId).then(
      (finding) => !cancelled && setState({ status: 'ready', finding, error: null }),
      (error) =>
        !cancelled &&
        setState({
          status: error?.status === 404 || error?.code === 'NOT_FOUND' ? 'notfound' : 'error',
          finding: null,
          error,
        }),
    );
    return () => {
      cancelled = true;
    };
  }, [findingId]);

  useEffect(() => load(), [load]);

  // Focus management + scroll lock.
  useEffect(() => {
    const opener = openerRef.current;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    closeRef.current?.focus();
    return () => {
      document.body.style.overflow = prevOverflow;
      if (opener && typeof opener.focus === 'function' && document.contains(opener)) opener.focus();
    };
  }, []);

  function onKeyDown(e) {
    if (e.key === 'Escape') {
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key !== 'Tab') return;
    const nodes = Array.from(panelRef.current?.querySelectorAll(FOCUSABLE) || []).filter(
      (n) => !n.hasAttribute('disabled') && n.getAttribute('aria-hidden') !== 'true',
    );
    if (nodes.length === 0) {
      e.preventDefault();
      return;
    }
    const first = nodes[0];
    const last = nodes[nodes.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || !panelRef.current.contains(active))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (active === last || !panelRef.current.contains(active))) {
      e.preventDefault();
      first.focus();
    }
  }

  function handleUpdated(updated) {
    setState({ status: 'ready', finding: updated, error: null });
    onChanged?.(updated);
  }

  const f = state.finding;

  return createPortal(
    <div className="drawer-root" onKeyDown={onKeyDown}>
      <div className="drawer-backdrop" data-testid="drawer-backdrop" onClick={onClose} />
      <aside
        ref={panelRef}
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-busy={state.status === 'loading'}
      >
        <header className="drawer__header">
          <div className="drawer__heading">
            <h2 id={titleId} className="drawer__title">
              {f ? f.vulnId : 'Finding details'}
            </h2>
            {f ? <p className="drawer__summary">{f.summary}</p> : null}
          </div>
          <button ref={closeRef} type="button" className="btn drawer__close" onClick={onClose} aria-label="Close finding details">
            Close
          </button>
        </header>

        <div className="drawer__body">
          {state.status === 'loading' && <Loading label="Loading finding..." />}
          {state.status === 'notfound' && (
            <ErrorState title="Finding not found" message="It may have been removed, or you may not have access to it." />
          )}
          {state.status === 'error' && (
            <ErrorState title="Could not load this finding" message={state.error?.message} onRetry={load} />
          )}
          {state.status === 'ready' && f && <FindingContent finding={f} role={role} onUpdated={handleUpdated} />}
        </div>
      </aside>
    </div>,
    document.body,
  );
}

function Section({ title, children }) {
  return (
    <section className="drawer-section">
      <h3 className="drawer-section__title">{title}</h3>
      {children}
    </section>
  );
}

function FindingContent({ finding: f, role, onUpdated }) {
  const cvss = parseCvssVector(f.cvssVector);
  const fixCommands = f.recommendedFix ? upgradeCommands(f.package.ecosystem, f.package.name, f.recommendedFix) : null;
  const canModify = role === 'admin' || role === 'analyst';
  const path = Array.isArray(f.dependencyPath) ? f.dependencyPath : [];

  return (
    <>
      <div className="drawer__meta">
        <SeverityBadge severity={f.severity} />
        <span className="drawer__score">
          {typeof f.score === 'number' ? `CVSS ${f.score.toFixed(1)}` : 'No CVSS score'}
        </span>
        {f.status === 'ignored' && <span className="tag tag--ignored">Ignored</span>}
      </div>

      <Section title="Severity">
        {f.cvssVector ? (
          <>
            <p className="mono drawer__vector" data-testid="cvss-vector">{f.cvssVector}</p>
            {cvss ? (
              <dl className="metric-list" aria-label="CVSS vector breakdown">
                {cvss.metrics.map((m) => (
                  <div key={m.key} className="metric-list__row">
                    <dt>
                      {m.label} <span className="mono muted">({m.key}:{m.value})</span>
                    </dt>
                    <dd>{m.text}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="muted">The vector could not be broken down into metrics.</p>
            )}
          </>
        ) : (
          <p className="muted">No CVSS vector is available for this finding.</p>
        )}
        {f.scoring?.explanation && <p className="drawer__explain">{f.scoring.explanation}</p>}
      </Section>

      <Section title="Affected package">
        <p>
          <strong className="mono">{f.package.name}@{f.package.version}</strong>{' '}
          <span className="tag">{f.package.ecosystem}</span>{' '}
          <span className="tag">{f.direct ? 'Direct' : 'Transitive'}</span>
        </p>
        {path.length > 0 && (
          <>
            <p className="muted drawer__label" id="dep-path-label">Dependency path</p>
            <ol className="dep-path" aria-labelledby="dep-path-label">
              {path.map((step, i) => (
                <li key={`${step}-${i}`} aria-current={i === path.length - 1 ? 'true' : undefined}>
                  <span className="mono">{step}</span>
                </li>
              ))}
            </ol>
          </>
        )}
      </Section>

      <Section title="Fix">
        {f.fixedVersions?.length ? (
          <p>
            Fixed in:{' '}
            {f.fixedVersions.map((v) => (
              <span key={v} className="tag mono">{v}</span>
            ))}
          </p>
        ) : (
          <p className="muted">No fixed version is known yet.</p>
        )}
        {f.recommendedFix && (
          <p>
            Recommended: <strong className="mono">{f.package.name}@{f.recommendedFix}</strong>
          </p>
        )}
        {f.recommendedFix && fixCommands && (
          <ul className="cmd-list">
            {fixCommands.map((c) => (
              <li key={c.label} className="cmd-list__row">
                <code className="cmd-list__code" data-testid={`cmd-${c.label}`}>{c.command}</code>
                <CopyButton text={c.command} label={`Copy ${c.label} command`} />
              </li>
            ))}
          </ul>
        )}
        {f.recommendedFix && !fixCommands && (
          <p className="muted">An upgrade command is not shown because the package name or version has unexpected characters.</p>
        )}
      </Section>

      {f.details && (
        <Section title="Advisory details">
          {/* Advisory text is untrusted: render as plain text only, keep line breaks. */}
          <div className="drawer__details">{f.details}</div>
        </Section>
      )}

      <Section title="Linked CVEs">
        {f.cves?.length ? (
          <ul className="cve-list">
            {f.cves.map((c) => (
              <CveItem key={c.cveId} cve={c} />
            ))}
          </ul>
        ) : (
          <p className="muted">No CVE ids are linked to this advisory.</p>
        )}
      </Section>

      <Section title="Weaknesses (CWE)">
        {f.cwes?.length ? (
          <p>
            {f.cwes.map((w) => (
              <span key={w} className="tag mono">{w}</span>
            ))}
          </p>
        ) : (
          <p className="muted">None listed.</p>
        )}
      </Section>

      <Section title="References">
        {f.references?.length ? (
          <ul className="ref-list">
            {f.references.map((r, i) => {
              const href = safeHttpUrl(r.url);
              return (
                <li key={`${r.url}-${i}`}>
                  <span className="tag">{r.type}</span>{' '}
                  {href ? (
                    <a href={href} target="_blank" rel="noopener noreferrer">{href}</a>
                  ) : (
                    <span className="muted ref-list__blocked" title="Link hidden: only http(s) URLs are clickable">
                      {String(r.url)}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="muted">No references.</p>
        )}
      </Section>

      <Section title="Dates">
        <dl className="date-list">
          <div><dt>Published</dt><dd>{formatDate(f.published)}</dd></div>
          <div><dt>Modified</dt><dd>{formatDate(f.modified)}</dd></div>
          <div><dt>First seen</dt><dd>{formatDate(f.firstSeenAt)}</dd></div>
        </dl>
      </Section>

      <IgnoreSection finding={f} canModify={canModify} onUpdated={onUpdated} />
    </>
  );
}

function CveItem({ cve }) {
  const href = safeHttpUrl(cve.url);
  return (
    <li className="cve-item">
      <div className="cve-item__head">
        {href ? (
          <a href={href} target="_blank" rel="noopener noreferrer" className="mono">{cve.cveId}</a>
        ) : (
          <span className="mono">{cve.cveId}</span>
        )}
        {!cve.error && <SeverityBadge severity={cve.severity} score={cve.score} />}
        {!cve.error && cve.source && <span className="muted">Source: {cve.source}</span>}
      </div>
      {cve.error === 'UPSTREAM_UNAVAILABLE' ? (
        <p className="muted cve-item__note">CVE details are temporarily unavailable (the CVE database could not be reached). Try again later.</p>
      ) : cve.error ? (
        <p className="muted cve-item__note">CVE details could not be loaded.</p>
      ) : (
        <>
          {cve.description && <p className="cve-item__desc">{cve.description}</p>}
          {cve.vector && <p className="mono muted">{cve.vector}</p>}
        </>
      )}
    </li>
  );
}

function IgnoreSection({ finding: f, canModify, onUpdated }) {
  const [step, setStep] = useState('idle'); // idle | editing | confirming
  const [reason, setReason] = useState('');
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const reasonId = useId();
  const errId = useId();
  const validation = validateReason(reason);
  const showValidation = touched && validation;

  async function submit(body) {
    setBusy(true);
    setError(null);
    try {
      const updated = await updateFinding(f.id, body);
      setStep('idle');
      setReason('');
      setTouched(false);
      onUpdated(updated);
    } catch (e) {
      setError(e?.message || 'Could not update the finding.');
    } finally {
      setBusy(false);
    }
  }

  function onContinue(e) {
    e.preventDefault();
    setTouched(true);
    if (validation) return;
    setStep('confirming');
  }

  if (f.status === 'ignored') {
    return (
      <Section title="Ignored">
        <p>
          This finding is ignored{f.ignore?.at ? ` since ${formatDateTime(f.ignore.at)}` : ''}.
        </p>
        {f.ignore?.reason && (
          <p className="drawer__details" data-testid="ignore-reason">Reason: {f.ignore.reason}</p>
        )}
        {canModify && (
          <button type="button" className="btn" disabled={busy} onClick={() => submit({ status: 'open' })}>
            Re-open
          </button>
        )}
        {error && <p role="alert" className="field-error">{error}</p>}
      </Section>
    );
  }

  if (!canModify) return null;

  return (
    <Section title="Ignore this finding">
      {step === 'idle' && (
        <button type="button" className="btn" onClick={() => setStep('editing')}>
          Ignore finding
        </button>
      )}

      {step === 'editing' && (
        <form onSubmit={onContinue} noValidate>
          <label htmlFor={reasonId} className="drawer__label">
            Reason ({REASON_MIN}-{REASON_MAX} characters)
          </label>
          <textarea
            id={reasonId}
            className="reason-input"
            rows={4}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            onBlur={() => setTouched(true)}
            aria-invalid={showValidation ? 'true' : 'false'}
            aria-describedby={showValidation ? errId : undefined}
          />
          <div className="reason-meta">
            <span className="muted">{reason.trim().length}/{REASON_MAX}</span>
          </div>
          {showValidation && (
            <p id={errId} role="alert" className="field-error">{validation}</p>
          )}
          <div className="btn-row">
            <button type="submit" className="btn btn--primary">Continue</button>
            <button type="button" className="btn" onClick={() => { setStep('idle'); setTouched(false); }}>Cancel</button>
          </div>
        </form>
      )}

      {step === 'confirming' && (
        <div role="group" aria-label="Confirm ignoring this finding">
          <p>Ignore <strong>{f.vulnId}</strong> for <span className="mono">{f.package.name}</span> in this repository? It will stay ignored in later scans.</p>
          <blockquote className="drawer__details">{reason.trim()}</blockquote>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn--danger"
              disabled={busy}
              onClick={() => submit({ status: 'ignored', reason: reason.trim() })}
            >
              {busy ? 'Ignoring...' : 'Confirm ignore'}
            </button>
            <button type="button" className="btn" disabled={busy} onClick={() => setStep('editing')}>Back</button>
          </div>
        </div>
      )}
      {error && <p role="alert" className="field-error">{error}</p>}
    </Section>
  );
}
