import './SeverityBadge.css';

const LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None', unknown: 'Unknown' };

/** Severity is always shown as a text label (never colour alone). */
export default function SeverityBadge({ severity, score }) {
  const key = Object.prototype.hasOwnProperty.call(LABELS, severity) ? severity : 'unknown';
  return (
    <span className={`sev-badge sev-badge--${key}`} data-severity={key}>
      {LABELS[key]}
      {typeof score === 'number' ? <span className="sev-badge__score">{score.toFixed(1)}</span> : null}
    </span>
  );
}
