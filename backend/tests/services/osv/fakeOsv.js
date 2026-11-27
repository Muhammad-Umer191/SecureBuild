// A fake OSV.dev for offline tests. `handler(method, path, body)` returns
// { status, body, headers } (or throws, to simulate a network error), and
// every call is recorded.
const fs = require('node:fs');
const path = require('node:path');

const FIXTURES = path.join(__dirname, 'fixtures');

function fakeFetch(handler) {
  const calls = [];
  let inFlight = 0;
  let maxInFlight = 0;
  const fetch = async (url, init = {}) => {
    const route = url.replace('https://api.osv.dev/v1', '');
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method: init.method, path: route, body });
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    try {
      await new Promise((r) => setImmediate(r));   // let other requests start, to measure concurrency
      const res = await handler(init.method, route, body);
      return new Response(typeof res.body === 'string' ? res.body : JSON.stringify(res.body ?? {}), {
        status: res.status ?? 200,
        headers: res.headers || {},
      });
    } finally {
      inFlight -= 1;
    }
  };
  return { fetch, calls, maxInFlight: () => maxInFlight };
}

/**
 * Fake OSV backed by data:
 *   vulnsByPurl: { purl: [{id, modified}] }
 *   records:     { id: record }
 */
function osvWith({ vulnsByPurl = {}, records = {} }) {
  return fakeFetch((method, route, body) => {
    if (method === 'POST' && route === '/querybatch') {
      return { body: { results: body.queries.map((q) => (vulnsByPurl[q.package.purl] ? { vulns: vulnsByPurl[q.package.purl] } : {})) } };
    }
    const id = decodeURIComponent(route.replace('/vulns/', ''));
    return records[id] ? { body: records[id] } : { status: 404, body: { code: 5, message: 'Vulnerability not found' } };
  });
}

/** The real responses saved from OSV.dev (lodash@4.17.11, left-pad@1.3.0, @babel/traverse@7.0.0). */
function realFixtures() {
  const batch = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'querybatch.json'), 'utf8'));
  const purls = ['pkg:npm/lodash@4.17.11', 'pkg:npm/left-pad@1.3.0', 'pkg:npm/%40babel/traverse@7.0.0'];
  const vulnsByPurl = {};
  batch.results.forEach((r, i) => { if (r.vulns) vulnsByPurl[purls[i]] = r.vulns; });
  const records = {};
  for (const f of fs.readdirSync(path.join(FIXTURES, 'records'))) {
    const rec = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'records', f), 'utf8'));
    records[rec.id] = rec;
  }
  return { purls, vulnsByPurl, records };
}

const noSleep = () => Promise.resolve();

module.exports = { fakeFetch, osvWith, realFixtures, noSleep };
