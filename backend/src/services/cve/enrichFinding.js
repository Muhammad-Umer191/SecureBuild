// Fills a saved Finding with CVE details from the fallback lookup:
//   - `cves`: one entry per CVE alias (score, source, description, link)
//   - when OSV gave no CVSS score: score/severity/vector from the best CVE record,
//     scoreSource = 'cvelistV5', and a scoring explanation that says so
//   - `cwes` from the CVE records when the advisory had none
// Upstream failures never throw: the CVE entry just gets error: 'UPSTREAM_UNAVAILABLE'.
const { Component, Finding } = require('../../models');
const { SEVERITY_RANK, THRESHOLDS, isValidScore } = require('./cveRecord');

const MAX_CVES = 5;
const BANDS = { critical: '9.0-10.0', high: '7.0-8.9', medium: '4.0-6.9', low: '0.1-3.9', none: '0.0' };

function explain(score, severity, version) {
  return `Score ${score} (CVSS ${version || '?'}) taken from the CVE record in cvelistV5 (fallback lookup); `
    + `severity band ${severity} = ${BANDS[severity] || '?'}`;
}

/** Already enriched, and nothing failed last time? Then skip the lookups. */
function isUpToDate(finding, cveIds) {
  const have = (finding.cves || []).filter((c) => !c.error).map((c) => c.cveId);
  return cveIds.length > 0 && cveIds.every((id) => have.includes(id));
}

/** Keeps the SBOM row's "max severity" in step after a finding's severity changes. */
async function refreshComponentSeverity(finding) {
  const purl = finding.package && finding.package.purl;
  if (!purl) return;
  const open = await Finding.find({ repo: finding.repo, 'package.purl': purl, status: 'open' }).select('severity').lean();
  const max = open.reduce((best, f) => ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[best] ?? -1) ? f.severity : best), null);
  await Component.updateOne({ repo: finding.repo, purl }, { $set: { vulnerabilityCount: open.length, maxSeverity: max } });
}

/**
 * @param {import('mongoose').Document} finding  a Finding document (not lean)
 * @param {{lookup: (id: string) => Promise<Object|null>}} cveLookup
 * @returns {Promise<import('mongoose').Document>} the same document, saved if changed
 */
async function enrichFinding(finding, cveLookup) {
  const cveIds = [...new Set((finding.cveIds || []).map((id) => String(id).toUpperCase()))]
    .filter((id) => /^CVE-\d{4}-\d{4,7}$/.test(id))
    .slice(0, MAX_CVES);
  if (!cveIds.length || isUpToDate(finding, cveIds)) return finding;

  const cves = await Promise.all(cveIds.map(async (cveId) => {
    try {
      const info = await cveLookup.lookup(cveId);
      return info || { cveId, error: 'NOT_FOUND' };
    } catch (err) {
      return { cveId, error: err.code === 'VALIDATION_ERROR' ? 'NOT_FOUND' : 'UPSTREAM_UNAVAILABLE' };
    }
  }));
  finding.cves = cves;

  if ((!finding.cwes || !finding.cwes.length)) {
    const cwes = [...new Set(cves.flatMap((c) => c.cwes || []))];
    if (cwes.length) finding.cwes = cwes;
  }

  let severityChanged = false;
  if (!isValidScore(finding.score)) {
    const best = cves
      .filter((c) => !c.error && isValidScore(c.score))
      .sort((a, b) => b.score - a.score)[0];
    if (best) {
      finding.score = best.score;
      finding.severity = best.severity;
      finding.cvssVector = best.vector;
      finding.scoreSource = 'cvelistV5';
      finding.scoring = { explanation: explain(best.score, best.severity, best.cvssVersion), thresholds: THRESHOLDS };
      severityChanged = true;
    }
  }

  await finding.save();
  if (severityChanged) await refreshComponentSeverity(finding);
  return finding;
}

module.exports = { enrichFinding, refreshComponentSeverity };
