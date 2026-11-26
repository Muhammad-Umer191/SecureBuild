// Scan module: the single entry point. Runs the whole pipeline for one repo:
//
//   clone -> discover -> parse    (the clone exists on disk only during these,
//                                  and is deleted before any network calls)
//         -> osv                  which advisories affect each package
//         -> findings             merged, scored, with fix versions and upgrades
//
// Errors are not swallowed: a failed clone or an OSV.dev outage fails the
// scan (CloneError / OsvError keep their code and `permanent` flag) and gets
// a `stage` label saying where it happened. Bad dependency files are only
// warnings, collected from every stage.
// Import from here (require('./services/scan')).
const { withClone: defaultWithClone } = require('../clone');
const { discoverDependencyFiles } = require('../discovery');
const { parseSources } = require('../parsers');
const { lookupVulnerabilities } = require('../osv');
const { buildFindings } = require('../findings');
const { registry: defaultRegistry } = require('../ecosystems');

/**
 * The result of one scan. Component, Finding and Upgrade are documented in
 * parsers/normalizeComponents.js and findings/index.js.
 * @typedef {Object} ScanResult
 * @property {string} repoUrl
 * @property {string} commitSha       exact commit that was scanned
 * @property {string} scannedAt       ISO time the scan started
 * @property {import('../parsers/normalizeComponents').Component[]} components  the SBOM
 * @property {import('../findings').Finding[]} findings   worst first
 * @property {import('../findings').Upgrade[]} upgrades   one per vulnerable package
 * @property {string[]} warnings      from every stage, in pipeline order
 * @property {{packages: number, vulnerablePackages: number, findings: number, fixable: number,
 *   bySeverity: Object<string, number>,
 *   durationMs: {clone: number, discover: number, parse: number, osv: number, findings: number, total: number}}} stats
 */

// Labels an error with the stage it came from (the innermost stage wins).
function tagStage(err, stage) {
  if (err && typeof err === 'object' && !err.stage) err.stage = stage;
  return err;
}

/**
 * @param {string} repoUrl  https://github.com/<owner>/<repo>
 * @param {Object} [opts]
 * @param {Object} [opts.clone]      { timeoutMs, maxSizeMb } (default: config.scanner)
 * @param {Object} [opts.discovery]  e.g. { skipDirs: [] } to also scan test folders
 * @param {Object} [opts.cache]      OSV record cache { get, set } (default: shared in-memory)
 * @param {Object} [opts.osvClient]  OSV client (default: the real OSV.dev)
 * @param {Object} [opts.registry]   ecosystem registry (default: npm + PyPI)
 * @param {(stage: string) => void} [opts.onProgress]  called as each stage starts
 * @param {Function} [opts.withClone]  replaces cloning (tests use a local folder)
 * @returns {Promise<ScanResult>}
 */
async function scan(repoUrl, opts = {}) {
  const {
    clone: cloneOpts = {},
    discovery: discoveryOpts = {},
    cache,
    osvClient,
    registry = defaultRegistry,
    onProgress = () => {},
    withClone = defaultWithClone,
  } = opts;

  const scannedAt = new Date().toISOString();
  const started = Date.now();
  const durationMs = {};

  // Runs one stage: reports progress, times it, labels its errors.
  async function stage(name, fn) {
    onProgress(name);
    const t = Date.now();
    try {
      return await fn();
    } catch (err) {
      throw tagStage(err, name);
    } finally {
      durationMs[name] = (durationMs[name] || 0) + Date.now() - t;
    }
  }

  // 1-3. clone, discover, parse. withClone deletes the clone when this returns.
  onProgress('clone');
  const cloneStarted = Date.now();
  let cloned;
  try {
    cloned = await withClone(repoUrl, async ({ dir, commitSha }) => {
      durationMs.clone = Date.now() - cloneStarted;
      const discovery = await stage('discover', () => discoverDependencyFiles(dir, { ...discoveryOpts, registry }));
      const parsed = await stage('parse', () => parseSources(dir, discovery.sources, { registry }));
      return { commitSha, components: parsed.components, warnings: [...discovery.warnings, ...parsed.warnings] };
    }, cloneOpts);
  } catch (err) {
    if (durationMs.clone === undefined) durationMs.clone = Date.now() - cloneStarted;
    throw tagStage(err, 'clone');
  }
  const { commitSha, components } = cloned;

  // 4. OSV lookup (makes no requests when there are no packages).
  const osv = await stage('osv', () => lookupVulnerabilities(components, { cache, client: osvClient }));

  // 5. Findings.
  const result = await stage('findings', () => buildFindings(components, osv.matches, { registry }));
  durationMs.total = Date.now() - started;

  return {
    repoUrl,
    commitSha,
    scannedAt,
    components,
    findings: result.findings,
    upgrades: result.upgrades,
    warnings: [...cloned.warnings, ...osv.warnings, ...result.warnings],
    stats: {
      packages: components.length,
      vulnerablePackages: result.upgrades.length,
      findings: result.stats.findings,
      fixable: result.stats.fixable,
      bySeverity: result.stats.bySeverity,
      durationMs,
    },
  };
}

module.exports = { scan };
