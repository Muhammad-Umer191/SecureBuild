// Severity labels, CVSS bands and ranking, shared by the whole services folder.
//
// Two casings are in use: the scan pipeline (findings/, cyclonedx/) works in
// UPPERCASE ('CRITICAL'), the database and the CVE module in lowercase
// ('critical'). Both are derived from the one list below.

const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'none', 'unknown']);

/** Lowest score of each CVSS 3.x / 4.0 band. */
const THRESHOLDS = Object.freeze({ critical: 9.0, high: 7.0, medium: 4.0, low: 0.1 });

/** Human-readable range of each band, for scoring explanations. */
const BANDS = Object.freeze({
  critical: '9.0-10.0', high: '7.0-8.9', medium: '4.0-6.9', low: '0.1-3.9', none: '0.0',
});

/** Worst = highest. Lowercase keys. */
const SEVERITY_RANK = Object.freeze({ critical: 5, high: 4, medium: 3, low: 2, none: 1, unknown: 0 });

/** Same ranking with UPPERCASE keys, for the pipeline. */
const SEVERITY_RANK_UPPER = Object.freeze(Object.fromEntries(
  Object.entries(SEVERITY_RANK).map(([k, v]) => [k.toUpperCase(), v]),
));

const isValidScore = (s) => typeof s === 'number' && Number.isFinite(s) && s >= 0 && s <= 10;

/** Score -> lowercase severity band. CVSS v2 has no "critical" band. */
function severityFromScore(score, cvssVersion = '3.1') {
  if (!isValidScore(score)) return 'unknown';
  if (String(cvssVersion).startsWith('2')) {
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  }
  if (score >= THRESHOLDS.critical) return 'critical';
  if (score >= THRESHOLDS.high) return 'high';
  if (score >= THRESHOLDS.medium) return 'medium';
  if (score >= THRESHOLDS.low) return 'low';
  return 'none';
}

/**
 * Free-form label ("CRITICAL", "Moderate", "important") -> one of SEVERITIES,
 * or null when it isn't a severity at all. Keeps arbitrary text out of the
 * database's fixed set of values.
 */
function normalizeSeverity(text) {
  if (typeof text !== 'string') return null;
  const t = text.trim().toLowerCase();
  if (SEVERITIES.includes(t)) return t;
  if (t === 'moderate') return 'medium';
  if (t === 'important') return 'high';
  if (t === 'info' || t === 'informational') return 'none';
  return null;
}

module.exports = {
  SEVERITIES,
  THRESHOLDS,
  BANDS,
  SEVERITY_RANK,
  SEVERITY_RANK_UPPER,
  isValidScore,
  severityFromScore,
  normalizeSeverity,
};
