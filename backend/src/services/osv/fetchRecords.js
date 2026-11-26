// Step 2 of the lookup: download the full advisory for each unique ID.
//
// GET /v1/vulns/{id} returns the whole OSV record: summary, aliases (e.g. its
// CVE), severity (CVSS vector), affected version ranges, references.
// - Each ID is fetched once, even if many packages share it.
// - At most `concurrency` requests run at the same time.
// - Records are cached by id + modified, so unchanged advisories are reused.
// - Withdrawn advisories (retracted by their publisher) are dropped.
const { OsvError } = require('./osvClient');
const { runPool } = require('./pool');
const { isObject } = require('../common/objects');
const { listNames } = require('../common/warnings');

/**
 * @param {Object} client             from createOsvClient
 * @param {Map<string, string>} ids    advisory id -> modified
 * @param {Object} opts
 * @param {Object} opts.cache          { get, set }
 * @param {number} [opts.concurrency=8]
 * @returns {Promise<{records: Map<string, Object>, warnings: string[],
 *   stats: {fetched: number, fromCache: number, withdrawn: number, missing: number}}>}
 */
async function fetchRecords(client, ids, { cache, concurrency = 8 }) {
  const records = new Map();
  const missing = [];
  const stats = { fetched: 0, fromCache: 0, withdrawn: 0, missing: 0 };

  await runPool([...ids], concurrency, async ([id, modified]) => {
    const key = `osv:${id}@${modified}`;
    let record = await cache.get(key);

    if (record) {
      stats.fromCache += 1;
    } else {
      const { status, body } = await client.getJson(`/vulns/${encodeURIComponent(id)}`);
      if (status === 404) {
        missing.push(id);
        return;
      }
      if (status !== 200) {
        throw new OsvError('OSV_REJECTED', `OSV.dev rejected the request for ${id} (HTTP ${status})`, { permanent: true });
      }
      if (!isObject(body) || typeof body.id !== 'string') {
        throw new OsvError('OSV_BAD_RESPONSE', `OSV.dev returned an unusable record for ${id}`);
      }
      record = body;
      stats.fetched += 1;
      await cache.set(key, record);
    }

    if (record.withdrawn) {
      stats.withdrawn += 1;
      return;
    }
    records.set(id, record);
  });

  stats.missing = missing.length;
  const warnings = missing.length
    ? [`OSV.dev no longer has ${missing.length} advisor${missing.length === 1 ? 'y' : 'ies'} it listed, so ${missing.length === 1 ? 'it was' : 'they were'} skipped: ${listNames(missing.sort())}`]
    : [];
  return { records, warnings, stats };
}

module.exports = { fetchRecords };
