// scannerService.js
// Thin adapter between the HTTP/worker layer and the real scan pipeline.
// The pipeline lives in services/scan/index.js (clone → discover → parse → osv → findings).
// This file translates the pipeline's ScanResult into the flat shapes the DB models expect.
//
// The worker (worker/scanWorker.js) calls scanRepository() or refreshRepository() and stores
// whatever this returns.  Any change to what the DB needs happens here, not in the pipeline.

const { scan } = require('./scan');
const { toCycloneDX } = require('./cyclonedx');
const logger = require('../utils/logger');

// ─── severity mapping ───────────────────────────────────────────────────────
// The pipeline uses uppercase ('CRITICAL'); the DB Finding model uses lowercase.
function lcSeverity(s) {
  if (!s) return 'unknown';
  const m = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', NONE: 'none', UNKNOWN: 'unknown' };
  return m[s.toUpperCase()] || 'unknown';
}

// ─── map one pipeline Finding to the DB Finding sub-document shape ───────────
function mapFinding(f, componentByPurl = new Map()) {
  const comp = componentByPurl.get(f.purl) || {};
  // vulnIds: pipeline puts all IDs first; we use them in order
  const vulnId   = f.vulnIds[0];
  const cveIds   = f.cves || [];
  const aliases  = f.vulnIds.slice(1);

  // CVSS: pipeline stores { v31: { vector, score }, v40: { vector, score } }
  let cvssVector = null;
  let score      = null;
  let scoreSource = null;
  if (f.cvss && f.cvss.v31) {
    cvssVector  = f.cvss.v31.vector;
    score       = f.cvss.v31.score;
    scoreSource = 'osv';
  } else if (f.cvss && f.cvss.v40) {
    cvssVector  = f.cvss.v40.vector;
    score       = f.cvss.v40.score;
    scoreSource = 'osv';
  }

  const severity     = lcSeverity(f.severity);
  const fixedVersions = f.fixedVersion ? [f.fixedVersion] : [];
  const hasFix       = fixedVersions.length > 0;

  // scoring explanation matches the frontend contract
  const THRESHOLDS = { critical: 9.0, high: 7.0, medium: 4.0, low: 0.1 };
  const bands = { critical: '9.0-10.0', high: '7.0-8.9', medium: '4.0-6.9', low: '0.1-3.9', none: '0.0' };
  let explanation;
  if (score === null || score === undefined) {
    explanation = 'No CVSS score found in the OSV advisory, so the severity is unknown. Review it manually.';
  } else {
    const ver = cvssVector ? cvssVector.slice(5, 8) : '?';
    explanation = `Score ${score} (CVSS ${ver}) from OSV advisory; severity band ${severity} = ${bands[severity] || '?'}`;
  }

  return {
    vulnId,
    aliases,
    cveIds,
    // summary / details come from the OSV record inside the pipeline
    summary:        f.summary    || vulnId,
    details:        f.details    || '',
    package: {
      name:       comp.name      || decodeURIComponent(f.purl.split('/').pop().split('@')[0]),
      version:    comp.version   || decodeURIComponent(f.purl.split('@').pop()),
      ecosystem:  comp.ecosystem || 'npm',
      purl:       f.purl,
    },
    direct:         comp.direct  ?? false,
    cvssVector,
    score,
    severity,
    scoreSource,
    hasFix,
    fixedVersions,
    recommendedFix: fixedVersions[0] || null,
    dependencyPath: f.dependencyPath || [],
    references:     (f.references || []).map((r) => ({ type: 'ADVISORY', url: r })),
    cwes:           f.cwes       || [],
    cves:           [],             // enriched later by F2's fallback lookup
    scoring:        { explanation, thresholds: THRESHOLDS },
    published:      f.published  ? new Date(f.published) : null,
    modified:       f.modified   ? new Date(f.modified)  : null,
  };
}

// ─── map pipeline Component to DB Component shape ────────────────────────────
function mapComponent(c) {
  return {
    name:    c.name,
    version: c.version,
    ecosystem: c.ecosystem,
    purl:    c.purl,
    direct:  c.direct   ?? false,
    licenses: c.license ? [c.license] : [],
    // vulnerability counts are recalculated by the worker after findings are saved
    vulnerabilityCount: 0,
    maxSeverity:        null,
  };
}

// ─── public API ──────────────────────────────────────────────────────────────

/**
 * Full scan of a GitHub repo.
 * @param {string} repoUrl
 * @param {object} [opts]  passed through to scan() (clone / discovery overrides for tests)
 * @returns {Promise<{ commitSha: string|null, findings: object[], components: object[], cyclonedx: object }>}
 */
async function scanRepository(repoUrl, opts = {}) {
  logger.info('[scannerService] scanRepository: %s', repoUrl);
  const result = await scan(repoUrl, opts);

  if (result.warnings.length) {
    logger.info('[scannerService] warnings for %s: %s', repoUrl, result.warnings.join(' | '));
  }

  const componentByPurl = new Map(result.components.map((c) => [c.purl, c]));

  return {
    commitSha:  result.commitSha,
    findings:   result.findings.map((f) => mapFinding(f, componentByPurl)),
    components: result.components.map(mapComponent),
    cyclonedx:  toCycloneDX(result),
  };
}

/**
 * Refresh scan – same as a full scan for now.
 * Returns hasNewCommits=true whenever the commitSha has changed.
 * @param {string} repoUrl
 * @param {string|null} lastCommitSha
 * @param {object} [opts]
 */
async function refreshRepository(repoUrl, lastCommitSha = null, opts = {}) {
  logger.info('[scannerService] refreshRepository: %s (last=%s)', repoUrl, lastCommitSha);
  const result = await scan(repoUrl, opts);

  if (result.warnings.length) {
    logger.info('[scannerService] warnings for %s: %s', repoUrl, result.warnings.join(' | '));
  }

  const hasNewCommits = result.commitSha !== lastCommitSha;
  const componentByPurl = new Map(result.components.map((c) => [c.purl, c]));

  return {
    hasNewCommits,
    commitSha:  result.commitSha,
    findings:   result.findings.map((f) => mapFinding(f, componentByPurl)),
    components: result.components.map(mapComponent),
    cyclonedx:  hasNewCommits ? toCycloneDX(result) : null,
  };
}

module.exports = { scanRepository, refreshRepository };
