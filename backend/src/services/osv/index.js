// OSV module: finds the known vulnerabilities for every package in the SBOM.
//
//   1. queryBatch     purls -> advisory IDs (up to 1,000 packages per request)
//   2. fetchRecords   unique IDs -> full advisory records (cached, max 8 at once)
//   3. matches        each vulnerable package with its records
//
// Packages are identified only by purl, so nothing here is ecosystem-specific.
// If OSV.dev can't be reached, this throws OsvError: a half-checked scan must
// never look like "no vulnerabilities".
// Import from here (require('./services/osv')).
const { createOsvClient, OsvError } = require('./osvClient');
const { createMemoryCache } = require('./cache');
const { queryBatch } = require('./queryBatch');
const { fetchRecords } = require('./fetchRecords');

// Shared by every scan in this process.
const defaultCache = createMemoryCache();

/**
 * @param {{purl: string}[]} components  the SBOM from parsers.parseSources
 * @param {Object} [opts]
 * @param {Object} [opts.cache]         { get, set } (default: shared in-memory cache)
 * @param {Object} [opts.client]        from createOsvClient (default: real OSV.dev)
 * @param {number} [opts.concurrency=8] max advisory downloads at once
 * @returns {Promise<{
 *   matches: {purl: string, records: Object[]}[],
 *   warnings: string[],
 *   stats: {queried, vulnerablePackages, advisories, fetched, fromCache, withdrawn, missing}
 * }>}
 */
async function lookupVulnerabilities(components, { cache = defaultCache, client, concurrency = 8 } = {}) {
  const osv = client || createOsvClient();
  const purls = [...new Set(components.map((c) => c.purl))].sort();

  const idsByPurl = await queryBatch(osv, purls);

  // One download per advisory, however many packages it affects.
  const allIds = new Map();
  for (const ids of idsByPurl.values()) {
    for (const [id, modified] of ids) allIds.set(id, modified);
  }
  const { records, warnings, stats } = await fetchRecords(osv, allIds, { cache, concurrency });

  const matches = [];
  for (const purl of purls) {
    const found = [...idsByPurl.get(purl).keys()].sort().map((id) => records.get(id)).filter(Boolean);
    if (found.length) matches.push({ purl, records: found });
  }

  return {
    matches,
    warnings,
    stats: {
      queried: purls.length,
      vulnerablePackages: matches.length,
      advisories: records.size,
      ...stats,
    },
  };
}

module.exports = { lookupVulnerabilities, createOsvClient, createMemoryCache, OsvError };
