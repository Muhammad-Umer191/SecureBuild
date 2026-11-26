// Findings module: turns raw OSV advisories into what a user reads.
//
//   1. mergeAliases   records describing the same flaw -> one finding
//   2. scoreRecords   CVSS vector -> 0-10 score -> severity
//   3. fixForGroup    the version that fixes this flaw for our installed version
//   4. upgrades       per package, the one version that closes all its findings
//
// Ecosystem rules (name matching, version order) come from the registry.
// Import from here (require('./services/findings')).
const { registry: defaultRegistry } = require('../ecosystems');
const { listNames } = require('../common/warnings');
const { mergeAliases } = require('./mergeAliases');
const { scoreRecords, SEVERITY_RANK } = require('./cvssScore');
const { fixForGroup, recommendUpgrade } = require('./fixVersion');

/**
 * @typedef {Object} Finding
 * @property {string} purl
 * @property {string[]} vulnIds      all IDs of the flaw, record IDs first (GHSA first)
 * @property {string[]} cves         the CVE IDs among them
 * @property {string} summary
 * @property {string[]} references   URLs
 * @property {{v31?: {vector: string, score: number}, v40?: {vector: string, score: number}}} cvss
 * @property {number|null} score     highest available CVSS score
 * @property {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'NONE'|'UNKNOWN'} severity
 * @property {string|null} fixedVersion  lowest version that fixes THIS flaw; null = no fix known
 * @property {boolean} approximate   the package version was estimated (manifest fallback)
 */

/**
 * @typedef {Object} Upgrade
 * @property {string} purl
 * @property {string} name
 * @property {string} ecosystem
 * @property {string} from           installed version
 * @property {string|null} to        one version that closes every fixable finding
 * @property {number} closes         findings fixed by upgrading to `to`
 * @property {number} unfixed        findings with no known fix
 * @property {string} worstSeverity  of the package's findings
 */

// Malware (MAL- IDs) first: it has no score but is more urgent than any bug.
const isMalware = (f) => f.vulnIds.some((id) => id.startsWith('MAL-'));
const bySeverity = (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
  || Number(isMalware(b)) - Number(isMalware(a))
  || (b.score ?? -1) - (a.score ?? -1)
  || a.purl.localeCompare(b.purl)
  || a.vulnIds[0].localeCompare(b.vulnIds[0]);

/**
 * @param {Object[]} components  the SBOM (parsers.parseSources)
 * @param {{purl: string, records: Object[]}[]} matches  from osv.lookupVulnerabilities
 * @param {{registry?: Object}} [opts]
 * @returns {{findings: Finding[], upgrades: Upgrade[], warnings: string[], stats: Object}}
 */
function buildFindings(components, matches, { registry = defaultRegistry } = {}) {
  const componentByPurl = new Map(components.map((c) => [c.purl, c]));
  const findings = [];
  const upgrades = [];
  const badVectors = [];
  const uncomparable = new Set();
  let records = 0;

  for (const { purl, records: pkgRecords } of matches) {
    const component = componentByPurl.get(purl);
    if (!component) continue;   // OSV answered for a purl we didn't ask about
    const eco = registry.get(component.ecosystem);
    records += pkgRecords.length;

    const pkgFindings = mergeAliases(pkgRecords).map((group) => {
      const scored = scoreRecords(group.records);
      badVectors.push(...scored.badVectors);
      const { fix, invalid } = fixForGroup(group.records, component, eco);
      if (invalid) uncomparable.add(group.vulnIds[0]);
      return {
        purl,
        vulnIds: group.vulnIds,
        cves: group.cves,
        summary: group.summary,
        references: group.references,
        cvss: scored.cvss,
        score: scored.score,
        severity: scored.severity,
        fixedVersion: fix,
        approximate: component.approximate === true,
      };
    });

    const upgrade = recommendUpgrade(pkgFindings.map((f) => f.fixedVersion), eco);
    upgrades.push({
      purl,
      name: component.name,
      ecosystem: component.ecosystem,
      from: component.version,
      ...upgrade,
      worstSeverity: [...pkgFindings].sort(bySeverity)[0].severity,
    });
    findings.push(...pkgFindings);
  }

  findings.sort(bySeverity);
  upgrades.sort((a, b) => SEVERITY_RANK[b.worstSeverity] - SEVERITY_RANK[a.worstSeverity]
    || b.closes + b.unfixed - (a.closes + a.unfixed)
    || a.purl.localeCompare(b.purl));

  const warnings = [];
  if (badVectors.length) {
    warnings.push(`Ignored ${badVectors.length} CVSS vector(s) that could not be scored: ${listNames(badVectors)}`);
  }
  if (uncomparable.size) {
    warnings.push(`Could not compare versions in some affected ranges, so their fix may be missing: ${listNames([...uncomparable])}`);
  }

  const severityCounts = Object.fromEntries(Object.keys(SEVERITY_RANK).map((s) => [s, 0]));
  findings.forEach((f) => { severityCounts[f.severity] += 1; });

  return {
    findings,
    upgrades,
    warnings,
    stats: {
      findings: findings.length,
      packages: upgrades.length,
      advisoryRecords: records,
      mergedAway: records - findings.length,
      bySeverity: severityCounts,
      fixable: findings.filter((f) => f.fixedVersion).length,
    },
  };
}

module.exports = { buildFindings };
