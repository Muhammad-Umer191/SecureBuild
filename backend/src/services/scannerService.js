// scannerService.js
// Thin adapter between the HTTP/worker layer and the real scan pipeline.
// The pipeline lives in services/scan/index.js (clone → discover → parse → osv → findings).
// This file translates the pipeline's ScanResult into the flat shapes the DB models expect.
//
// The worker (worker/scanWorker.js) calls scanRepository() for both a first scan and a
// refresh, and stores whatever this returns.  Any change to what the DB needs happens here, not in the pipeline.
//
// The pipeline has already decided score and severity; this file only copies them over.
// The SBOM download is built later from the saved data (services/sbomExport.js).

const { scan } = require('./scan');
const { isMalware } = require('./findings');
const { BANDS, THRESHOLDS, normalizeSeverity } = require('./common/severity');
const logger = require('../utils/logger');

/** The CVSS vector that produced the pipeline's score (v3.1 wins a tie). */
function vectorFor(cvss, score) {
  if (score === null || score === undefined || !cvss) return null;
  const match = [cvss.v31, cvss.v40].find((c) => c && c.score === score);
  return match ? match.vector : null;
}

/** Text the frontend shows under "why this severity". */
function explain(f, score, vector, severity) {
  if (score !== null && score !== undefined) {
    const ver = vector ? vector.slice(5, 8) : '?';
    return `Score ${score} (CVSS ${ver}) from OSV advisory; severity band ${severity} = ${BANDS[severity] || '?'}`;
  }
  if (isMalware(f)) {
    return 'Malicious package (MAL- advisory): rated critical regardless of CVSS.';
  }
  if (severity !== 'unknown') {
    return `No CVSS score in the OSV advisory; severity ${severity} comes from the advisory database's own label.`;
  }
  return 'No CVSS score found in the OSV advisory, so the severity is unknown. Review it manually.';
}

// ─── map one pipeline Finding to the DB Finding shape ────────────────────────
// Every finding belongs to a component the pipeline found, so `comp` is always there.
function mapFinding(f, componentByPurl) {
  const comp = componentByPurl.get(f.purl);
  const score = f.score ?? null;
  const cvssVector = vectorFor(f.cvss, score);
  const severity = normalizeSeverity(f.severity) || 'unknown';
  const fixedVersions = f.fixedVersion ? [f.fixedVersion] : [];

  return {
    vulnId:  f.vulnIds[0],
    aliases: f.vulnIds.slice(1),
    cveIds:  f.cves || [],
    summary: f.summary || f.vulnIds[0],
    package: {
      name:      comp.name,
      version:   comp.version,
      ecosystem: comp.ecosystem,
      purl:      f.purl,
    },
    direct:         comp.direct === true,
    cvssVector,
    score,
    severity,
    scoreSource:    score === null ? null : 'osv',
    hasFix:         fixedVersions.length > 0,
    fixedVersions,
    recommendedFix: fixedVersions[0] || null,
    references:     (f.references || []).map((r) => ({ type: 'ADVISORY', url: r })),
    // Cleared on every scan; the CVE module (services/cve) fills them again
    // when the finding is opened.
    cwes:           [],
    cves:           [],
    scoring:        { explanation: explain(f, score, cvssVector, severity), thresholds: THRESHOLDS },
  };
}

// ─── map pipeline Component to DB Component shape ────────────────────────────
function mapComponent(c) {
  return {
    name:      c.name,
    version:   c.version,
    ecosystem: c.ecosystem,
    purl:      c.purl,
    direct:    c.direct === true,
    licenses:  c.license ? [c.license] : [],
    // vulnerability counts are recalculated by the worker after findings are saved
    vulnerabilityCount: 0,
    maxSeverity:        null,
  };
}

// ─── public API ──────────────────────────────────────────────────────────────

/**
 * Full scan of a GitHub repo, mapped for the database.
 * @param {string} repoUrl
 * @param {object} [opts]  passed through to scan() (clone / discovery overrides for tests)
 * @returns {Promise<{ commitSha: string|null, findings: object[], components: object[] }>}
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
  };
}

module.exports = { scanRepository };
