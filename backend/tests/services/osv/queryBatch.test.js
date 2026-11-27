const { queryBatch } = require('../../../src/services/osv/queryBatch');
const { createOsvClient } = require('../../../src/services/osv/osvClient');
const { fakeFetch } = require('./fakeOsv');

const clientFor = (fake) => createOsvClient({ fetch: fake.fetch, sleep: () => Promise.resolve() });
const ids = (map) => [...map.keys()];

describe('queryBatch', () => {
  test('splits large inputs into requests of at most 1,000 and maps results back', async () => {
    const purls = Array.from({ length: 2500 }, (_, i) => `pkg:npm/p${i}@1.0.0`);
    // every 100th package has one advisory named after it
    const fake = fakeFetch((_m, _p, body) => ({
      body: { results: body.queries.map((q) => (q.package.purl.match(/p(\d+)@/)[1] % 100 === 0 ? { vulns: [{ id: `ID-${q.package.purl}`, modified: 'm' }] } : {})) },
    }));

    const result = await queryBatch(clientFor(fake), purls);
    expect(fake.calls.map((c) => c.body.queries.length)).toEqual([1000, 1000, 500]);
    expect(ids(result.get('pkg:npm/p1200@1.0.0'))).toEqual(['ID-pkg:npm/p1200@1.0.0']);
    expect(ids(result.get('pkg:npm/p1201@1.0.0'))).toEqual([]);
    expect([...result.values()].filter((m) => m.size).length).toBe(25);
  });

  test('follows next_page_token until all pages are read', async () => {
    const fake = fakeFetch((_m, _p, body) => ({
      body: {
        results: body.queries.map((q) => {
          if (q.package.purl !== 'pkg:pypi/django@3.2.0') return {};
          if (!q.page_token) return { vulns: [{ id: 'A', modified: '1' }], next_page_token: 'p2' };
          if (q.page_token === 'p2') return { vulns: [{ id: 'B', modified: '1' }], next_page_token: 'p3' };
          return { vulns: [{ id: 'C', modified: '1' }] };
        }),
      },
    }));
    const result = await queryBatch(clientFor(fake), ['pkg:pypi/django@3.2.0', 'pkg:pypi/six@1.16.0']);
    expect(ids(result.get('pkg:pypi/django@3.2.0'))).toEqual(['A', 'B', 'C']);
    // later pages only re-send the query that has more pages
    expect(fake.calls.map((c) => c.body.queries.map((q) => q.page_token || '-'))).toEqual([['-', '-'], ['p2'], ['p3']]);
  });

  test('a results count that does not match the queries is OSV_BAD_RESPONSE', async () => {
    const fake = fakeFetch(() => ({ body: { results: [{}] } }));
    await expect(queryBatch(clientFor(fake), ['pkg:npm/a@1.0.0', 'pkg:npm/b@1.0.0']))
      .rejects.toMatchObject({ code: 'OSV_BAD_RESPONSE', message: 'querybatch returned 1 results for 2 queries' });
  });

  test('a rejected query (e.g. 400) is a permanent OSV_REJECTED', async () => {
    const fake = fakeFetch(() => ({ status: 400, body: { code: 3, message: 'too many queries' } }));
    await expect(queryBatch(clientFor(fake), ['pkg:npm/a@1.0.0']))
      .rejects.toMatchObject({ code: 'OSV_REJECTED', permanent: true, message: 'OSV.dev rejected the query (HTTP 400: too many queries)' });
  });

  test('pagination that never ends is stopped', async () => {
    const fake = fakeFetch((_m, _p, body) => ({ body: { results: body.queries.map(() => ({ next_page_token: 'again' })) } }));
    await expect(queryBatch(clientFor(fake), ['pkg:npm/a@1.0.0'])).rejects.toMatchObject({ code: 'OSV_BAD_RESPONSE' });
    expect(fake.calls).toHaveLength(50);
  });

  test('odd entries in a result are ignored, not crashed on', async () => {
    const fake = fakeFetch(() => ({ body: { results: [{ vulns: [null, { id: 42 }, { id: 'GOOD' }] }] } }));
    const result = await queryBatch(clientFor(fake), ['pkg:npm/a@1.0.0']);
    expect(ids(result.get('pkg:npm/a@1.0.0'))).toEqual(['GOOD']);
  });
});
