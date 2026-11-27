// Step 1 of the lookup: which advisories affect each package version?
//
// POST /v1/querybatch takes up to 1,000 queries and answers, in the same
// order, with only the advisory IDs (plus their `modified` time):
//   { results: [ { vulns: [{ id, modified }] }, {}, ... ] }      {} = nothing known
// A query with very many advisories gets a `next_page_token`; that query is
// sent again with `page_token` until all pages are read.
const { OsvError } = require('./osvClient');
const { isObject } = require('../common/objects');

const BATCH_SIZE = 1000;   // OSV.dev rejects more ("too many queries")
const MAX_ROUNDS = 50;     // safety stop if pagination never ends

/**
 * @param {Object} client  from createOsvClient
 * @param {string[]} purls  unique purls
 * @returns {Promise<Map<string, Map<string, string>>>}  purl -> (advisory id -> modified)
 */
async function queryBatch(client, purls) {
  const idsByPurl = new Map(purls.map((p) => [p, new Map()]));

  for (let start = 0; start < purls.length; start += BATCH_SIZE) {
    let pending = purls.slice(start, start + BATCH_SIZE).map((purl) => ({ purl, pageToken: null }));

    for (let round = 1; pending.length; round += 1) {
      if (round > MAX_ROUNDS) {
        throw new OsvError('OSV_BAD_RESPONSE', `querybatch kept returning more pages after ${MAX_ROUNDS} rounds`);
      }
      const queries = pending.map((q) => ({
        package: { purl: q.purl },
        ...(q.pageToken ? { page_token: q.pageToken } : {}),
      }));

      const { status, body } = await client.postJson('/querybatch', { queries });
      if (status !== 200) {
        const detail = isObject(body) && typeof body.message === 'string' ? `: ${body.message}` : '';
        throw new OsvError('OSV_REJECTED', `OSV.dev rejected the query (HTTP ${status}${detail})`, { permanent: true });
      }
      const results = isObject(body) && Array.isArray(body.results) ? body.results : null;
      if (!results || results.length !== queries.length) {
        throw new OsvError('OSV_BAD_RESPONSE', `querybatch returned ${results ? results.length : 'no'} results for ${queries.length} queries`);
      }

      const nextRound = [];
      results.forEach((result, i) => {
        if (!isObject(result)) return;
        const ids = idsByPurl.get(pending[i].purl);
        for (const v of Array.isArray(result.vulns) ? result.vulns : []) {
          if (isObject(v) && typeof v.id === 'string') ids.set(v.id, typeof v.modified === 'string' ? v.modified : '');
        }
        if (typeof result.next_page_token === 'string' && result.next_page_token) {
          nextRound.push({ purl: pending[i].purl, pageToken: result.next_page_token });
        }
      });
      pending = nextRound;
    }
  }
  return idsByPurl;
}

module.exports = { queryBatch, BATCH_SIZE };
