// SBOM export (F2): CycloneDX 1.5 from what is saved in MongoDB.
//
// B2's exporter (services/cyclonedx) takes a ScanResult straight from the
// pipeline. Here the scan is long over, so the saved Component and Finding
// documents are turned back into that shape and passed through the same
// exporter, so both paths produce the same, schema-valid format.
//
// Sanitised on purpose: no user ids, no ignore reasons, ignored findings left out.
const { toCycloneDX } = require('./cyclonedx');

const SEVERITY_UPPER = {
  critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', none: 'NONE', unknown: 'UNKNOWN',
};

function cvssOf(f) {
  if (typeof f.score !== 'number' || !f.cvssVector) return {};
  const entry = { vector: f.cvssVector, score: f.score };
  if (f.cvssVector.startsWith('CVSS:4.0/')) return { v40: entry };
  if (f.cvssVector.startsWith('CVSS:3')) return { v31: entry };
  return {}; // CVSS v2 has no CycloneDX method in B2's exporter; the severity label still goes in
}

function toPipelineComponent(c) {
  return {
    name: c.name,
    version: c.version,
    ecosystem: c.ecosystem,
    purl: c.purl,
    direct: Boolean(c.direct),
    dev: false,
    license: (c.licenses && c.licenses[0]) || null,
    dependsOn: [],
    source: 'securebuild-scan',
    approximate: false,
  };
}

function toPipelineFinding(f) {
  return {
    purl: f.package.purl,
    vulnIds: [f.vulnId, ...(f.aliases || []).filter((a) => a !== f.vulnId)],
    cves: f.cveIds || [],
    summary: f.summary,
    references: (f.references || []).map((r) => r.url).filter(Boolean),
    cvss: cvssOf(f),
    score: typeof f.score === 'number' ? f.score : null,
    severity: SEVERITY_UPPER[f.severity] || 'UNKNOWN',
    fixedVersion: f.recommendedFix || (f.fixedVersions && f.fixedVersions[0]) || null,
    approximate: false,
  };
}

const RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1, UNKNOWN: 0 };

/**
 * @param {{repo: Object, scan: Object|null, components: Object[], findings: Object[]}} data  lean docs
 * @returns {Object} CycloneDX 1.5 document
 */
function buildSbom({ repo, scan, components, findings }) {
  const comps = components.map(toPipelineComponent);
  const known = new Set(comps.map((c) => c.purl));
  const pipelineFindings = findings
    .filter((f) => f.status !== 'ignored' && f.package && known.has(f.package.purl))
    .map(toPipelineFinding)
    // B2's exporter expects findings worst first
    .sort((a, b) => RANK[b.severity] - RANK[a.severity] || (b.score ?? -1) - (a.score ?? -1)
      || a.vulnIds[0].localeCompare(b.vulnIds[0]));

  const bom = toCycloneDX({
    repoUrl: repo.url,
    commitSha: (scan && scan.commitSha) || undefined,
    scannedAt: new Date((scan && scan.finishedAt) || Date.now()).toISOString(),
    components: comps,
    findings: pipelineFindings,
  });

  // The DB keeps only "direct or not", not who-depends-on-whom. Keep the one link we
  // know (repo -> its direct packages) instead of claiming every package has none.
  bom.dependencies = bom.dependencies.filter((d) => d.ref === repo.url);
  if (!bom.metadata.component.version) delete bom.metadata.component.version;
  return bom;
}

/** "https://github.com/owner/repo" -> "owner-repo-sbom.cdx.json", safe for a header. */
function sbomFileName(repo) {
  const base = String(repo.name || 'repo').replace('/', '-').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 100);
  return `${base}-sbom.cdx.json`;
}

module.exports = { buildSbom, sbomFileName };
