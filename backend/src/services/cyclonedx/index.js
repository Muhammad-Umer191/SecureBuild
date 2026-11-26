// CycloneDX module: exports a ScanResult as a CycloneDX 1.5 SBOM (JSON).
//
// CycloneDX (OWASP) is the standard SBOM format other tools read, e.g.
// Dependency-Track, other scanners, auditors. The document has:
//   metadata         which repo and commit, when, which tool
//   components       every package (purl, version, license, dev = "optional")
//   dependencies     the dependency graph
//   vulnerabilities  each flaw, its CVSS ratings, the fix, the affected packages
// Output is checked in tests against the official 1.5 schema (./schema).
// Import from here (require('./services/cyclonedx')).
const { randomUUID } = require('node:crypto');
const { version: packageVersion } = require('../../../package.json');
const { buildComponents } = require('./components');
const { buildVulnerabilities } = require('./vulnerabilities');

// "https://github.com/OWASP/NodeGoat" -> "OWASP/NodeGoat"
function repoName(url) {
  try {
    return new URL(url).pathname.replace(/^\/+|\/+$/g, '').replace(/\.git$/, '') || url;
  } catch {
    return url;
  }
}

/**
 * @param {import('../scan').ScanResult} result
 * @param {Object} [opts]
 * @param {string} [opts.serialNumber]  default: a new urn:uuid (pass one for reproducible output)
 * @param {string} [opts.toolVersion]   default: this backend's package.json version
 * @returns {Object} CycloneDX 1.5 document (JSON.stringify it to save)
 */
function toCycloneDX(result, { serialNumber = `urn:uuid:${randomUUID()}`, toolVersion = packageVersion } = {}) {
  const repoRef = result.repoUrl;
  const { components, dependencies } = buildComponents(result.components, repoRef);
  const componentsByPurl = new Map(result.components.map((c) => [c.purl, c]));

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp: result.scannedAt,
      tools: {
        components: [{ type: 'application', name: 'SecureBuild Scanner', version: toolVersion }],
      },
      component: {
        type: 'application',
        'bom-ref': repoRef,
        name: repoName(result.repoUrl),
        version: result.commitSha,
        externalReferences: [{ type: 'vcs', url: result.repoUrl }],
      },
    },
    components,
    dependencies,
    vulnerabilities: buildVulnerabilities(result.findings, componentsByPurl),
  };
}

module.exports = { toCycloneDX };
