// How bad is a flaw? Turns CVSS vectors into 0-10 scores and severity labels.
//
// A CVSS vector describes how a flaw can be exploited, e.g.
//   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H
//   attack over the Network, Low complexity, no Privileges or User action
//   needed, no Confidentiality impact, High Integrity and Availability impact
// The official formula (ae-cvss-calculator, checked against the Python `cvss`
// package) turns that into a score: 9.1 here. CVSS 3.x and 4.0 use different
// formulas, so each vector is scored with the class for its version.
const { Cvss3P0, Cvss3P1, Cvss4P0 } = require('ae-cvss-calculator');
const { isObject } = require('../common/objects');

const CALCULATORS = [
  ['CVSS:3.0/', Cvss3P0, 'v31'],   // 3.0 and 3.1 share the "v31" slot of the contract
  ['CVSS:3.1/', Cvss3P1, 'v31'],
  ['CVSS:4.0/', Cvss4P0, 'v40'],
];

/**
 * GitHub's own severity label, used only when an advisory has no CVSS vector.
 * GitHub says MODERATE where CVSS says MEDIUM; anything else unexpected is
 * ignored, so free-form data can't leak into our fixed severity values.
 */
function githubSeverity(label) {
  const s = String(label).toUpperCase();
  if (s === 'MODERATE') return 'MEDIUM';
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(s) ? s : undefined;
}

const SEVERITY_RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1, UNKNOWN: 0 };

/**
 * @param {string} vector
 * @returns {{version: 'v31'|'v40', score: number}|null}  null for a vector we can't score
 */
function scoreVector(vector) {
  if (typeof vector !== 'string') return null;
  const match = CALCULATORS.find(([prefix]) => vector.startsWith(prefix));
  if (!match) return null;
  const [, Calculator, version] = match;
  try {
    const score = new Calculator(vector).calculateScores().overall;
    return Number.isFinite(score) && score >= 0 && score <= 10 ? { version, score } : null;
  } catch {
    return null;    // malformed vector
  }
}

/** Standard CVSS bands: 9.0+ CRITICAL, 7.0+ HIGH, 4.0+ MEDIUM, above 0 LOW, 0 NONE. */
function severityFromScore(score) {
  if (score === null || score === undefined) return 'UNKNOWN';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}

/**
 * True when any ID of the group is a MAL- advisory: the package version is
 * malware (OpenSSF Malicious Packages), not a bug. It has no CVSS score, but
 * it can do damage at install time, even as a dev-only dependency.
 */
function isMalicious(records) {
  const ids = records.flatMap((r) => [r.id, ...(Array.isArray(r.aliases) ? r.aliases : [])]);
  return ids.some((id) => typeof id === 'string' && id.startsWith('MAL-'));
}

/**
 * Scores a group of records describing the same flaw: the highest v3.x and
 * the highest v4.0 score across all of them. Without any vector, falls back
 * to GitHub's severity label. Malware is always CRITICAL.
 * @param {Object[]} records  OSV records
 * @returns {{cvss: {v31?: {vector, score}, v40?: {vector, score}}, score: number|null,
 *            severity: string, badVectors: string[]}}
 */
function scoreRecords(records) {
  const result = scoreFromVectors(records);
  return isMalicious(records) ? { ...result, severity: 'CRITICAL' } : result;
}

function scoreFromVectors(records) {
  const cvss = {};
  const badVectors = [];

  for (const record of records) {
    for (const entry of Array.isArray(record.severity) ? record.severity : []) {
      if (!isObject(entry) || !['CVSS_V3', 'CVSS_V4'].includes(entry.type)) continue;
      const scored = scoreVector(entry.score);
      if (!scored) {
        badVectors.push(`${record.id}: ${entry.score}`);
        continue;
      }
      const current = cvss[scored.version];
      if (!current || scored.score > current.score) {
        cvss[scored.version] = { vector: entry.score, score: scored.score };
      }
    }
  }

  const scores = Object.values(cvss).map((c) => c.score);
  if (scores.length) {
    const score = Math.max(...scores);
    return { cvss, score, severity: severityFromScore(score), badVectors };
  }

  // No usable vector: GitHub's label (worst one in the group), score unknown.
  const labels = records
    .map((r) => (isObject(r.database_specific) ? githubSeverity(r.database_specific.severity) : undefined))
    .filter(Boolean)
    .sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a]);
  return { cvss, score: null, severity: labels[0] || 'UNKNOWN', badVectors };
}

module.exports = { scoreVector, scoreRecords, severityFromScore, isMalicious, SEVERITY_RANK };
