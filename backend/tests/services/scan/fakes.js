// Offline stand-ins for a full scan: a local fixture repo instead of a clone,
// and a fake OSV.dev that replays real saved advisories.
const { createOsvClient } = require('../../../src/services/osv');
const { makeRepo } = require('../helpers');
const { text } = require('../fixtures');
const { realFixtures, fakeFetch } = require('../osv/fakeOsv');

const SHA = 'a'.repeat(40);
const { records } = realFixtures();

/** Stands in for clone.withClone and records when the "clone" is created and removed. */
function fakeWithClone(dir, log = []) {
  return async (_url, fn) => {
    log.push('cloned');
    try {
      return await fn({ dir, commitSha: SHA });
    } finally {
      log.push('clone removed');
    }
  };
}

/** Fake OSV.dev: lodash@4.17.21 (from the npm fixture) has two real advisories. */
function fakeOsvClient(log = []) {
  const vulnsByPurl = {
    'pkg:npm/lodash@4.17.21': [
      { id: 'GHSA-r5fr-rjxr-66jc', modified: records['GHSA-r5fr-rjxr-66jc'].modified },
      { id: 'GHSA-xxjr-mmjv-4gpg', modified: records['GHSA-xxjr-mmjv-4gpg'].modified },
    ],
  };
  const fake = fakeFetch((method, route, body) => {
    log.push(`osv ${method}`);
    if (method === 'POST') return { body: { results: body.queries.map((q) => (vulnsByPurl[q.package.purl] ? { vulns: vulnsByPurl[q.package.purl] } : {})) } };
    return { body: records[decodeURIComponent(route.replace('/vulns/', ''))] };
  });
  return createOsvClient({ fetch: fake.fetch, sleep: () => Promise.resolve() });
}

/** A repo with the npm v3 and poetry fixtures (18 packages); caller removes it. */
function fixtureRepo(extra = {}) {
  return makeRepo({
    'package-lock.json': text('package-lock-v3.json'),
    'package.json': '{"name": "app"}',
    'api/poetry.lock': text('poetry-groups.lock'),
    'api/pyproject.toml': text('pyproject-poetry.toml'),
    'tests/fixtures/sample/package.json': '{}',   // skipped -> a discovery warning
    ...extra,
  });
}

module.exports = { SHA, fakeWithClone, fakeOsvClient, fixtureRepo };
