// CycloneDX `vulnerabilities`: one entry per flaw.
//
// Our findings are per package, but one advisory can affect several packages
// (two versions of tar, lodash and lodash.merge, ...). CycloneDX lists the
// flaw once and names every package it affects in `affects`, so findings are
// grouped by their primary ID.
const { severityFromScore } = require('../findings');

const osvSource = (id) => ({ name: 'OSV', url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` });

// Where to read about an alias ID.
function sourceFor(id) {
  if (id.startsWith('CVE-')) return { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}` };
  if (id.startsWith('GHSA-')) return { name: 'GitHub Advisory Database', url: `https://github.com/advisories/${encodeURIComponent(id)}` };
  return osvSource(id);
}

const lower = (severity) => severity.toLowerCase();
const isMalware = (ids) => ids.some((id) => id.startsWith('MAL-'));

/** CVSS ratings, plus a label-only rating when there is a severity but no score. */
function ratingsOf(finding, ids) {
  const source = osvSource(ids[0]);
  const ratings = [];
  const { v31, v40 } = finding.cvss;
  if (v31) {
    ratings.push({
      source,
      score: v31.score,
      severity: lower(severityFromScore(v31.score)),
      method: v31.vector.startsWith('CVSS:3.0/') ? 'CVSSv3' : 'CVSSv31',
      vector: v31.vector,
    });
  }
  if (v40) {
    ratings.push({ source, score: v40.score, severity: lower(severityFromScore(v40.score)), method: 'CVSSv4', vector: v40.vector });
  }
  if (isMalware(ids)) {
    ratings.push({ source, severity: 'critical', method: 'other', justification: 'Malicious package (MAL- advisory): rated critical regardless of CVSS' });
  } else if (!ratings.length && finding.severity !== 'UNKNOWN') {
    ratings.push({ source, severity: lower(finding.severity), method: 'other', justification: 'Severity label from the advisory database; no CVSS vector available' });
  }
  return ratings;
}

const unique = (values) => [...new Set(values)];

/**
 * @param {Object[]} findings     ScanResult.findings
 * @param {Map<string, Object>} componentsByPurl
 * @returns {Object[]} CycloneDX vulnerabilities
 */
function buildVulnerabilities(findings, componentsByPurl) {
  const groups = new Map();
  for (const f of findings) {
    const id = f.vulnIds[0];
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(f);
  }

  const entries = [...groups.entries()].map(([id, group]) => {
    // The worst-rated copy speaks for the flaw (findings arrive worst first).
    const [lead] = group;
    const ids = unique(group.flatMap((f) => f.vulnIds));
    const advisories = unique(group.flatMap((f) => f.references)).filter((u) => /^https?:\/\//i.test(u));
    const approximate = group.some((f) => f.approximate);

    const entry = {
      'bom-ref': id,
      id,
      source: osvSource(id),
      references: ids.slice(1).map((alias) => ({ id: alias, source: sourceFor(alias) })),
      ratings: ratingsOf(lead, ids),
      description: lead.summary,
      recommendation: group
        .map((f) => `${f.purl}: ${f.fixedVersion ? `upgrade to ${f.fixedVersion}` : 'no fixed version known'}`)
        .join('\n'),
      advisories: advisories.map((url) => ({ url })),
      affects: group.map((f) => ({
        ref: f.purl,
        versions: [{ version: componentsByPurl.get(f.purl).version, status: 'affected' }],
      })),
    };
    if (approximate) entry.properties = [{ name: 'securebuild:approximate', value: 'true' }];
    return entry;
  });

  // Findings arrive worst first (severity, malware first, then score), and the
  // groups keep that order, so the BOM lists flaws in the same order as the report.
  return entries;
}

module.exports = { buildVulnerabilities };
