const { lookupVulnerabilities, createOsvClient, createMemoryCache } = require('../../../src/services/osv');
const { osvWith, realFixtures, fakeFetch } = require('./fakeOsv');

const setup = (data) => {
  const fake = osvWith(data);
  return { fake, client: createOsvClient({ fetch: fake.fetch, sleep: () => Promise.resolve() }) };
};
const component = (purl) => ({ purl });
const record = (id, extra = {}) => ({ id, modified: 'm1', summary: `about ${id}`, ...extra });

describe('lookupVulnerabilities with real OSV responses', () => {
  test('finds lodash and @babel/traverse advisories; left-pad is clean', async () => {
    const data = realFixtures();
    const { client } = setup(data);
    const { matches, warnings, stats } = await lookupVulnerabilities(data.purls.map(component), {
      client, cache: createMemoryCache(),
    });

    expect(matches.map((m) => [m.purl, m.records.length])).toEqual([
      ['pkg:npm/%40babel/traverse@7.0.0', 1],
      ['pkg:npm/lodash@4.17.11', 6],
    ]);
    const prototypePollution = matches[1].records.find((r) => r.id === 'GHSA-jf85-cpcp-j695');
    expect(prototypePollution.aliases).toContain('CVE-2019-10744');
    expect(prototypePollution.severity[0].type).toBe('CVSS_V3');
    expect(warnings).toEqual([]);
    expect(stats).toEqual({
      queried: 3, vulnerablePackages: 2, advisories: 7, fetched: 7, fromCache: 0, withdrawn: 0, missing: 0,
    });
  });
});

describe('lookupVulnerabilities behaviour', () => {
  test('duplicate purls are queried once; clean packages are left out', async () => {
    const { fake, client } = setup({ vulnsByPurl: { 'pkg:npm/a@1.0.0': [{ id: 'X', modified: 'm1' }] }, records: { X: record('X') } });
    const { matches } = await lookupVulnerabilities(
      [component('pkg:npm/a@1.0.0'), component('pkg:npm/a@1.0.0'), component('pkg:npm/clean@1.0.0')],
      { client, cache: createMemoryCache() },
    );
    expect(fake.calls[0].body.queries.map((q) => q.package.purl)).toEqual(['pkg:npm/a@1.0.0', 'pkg:npm/clean@1.0.0']);
    expect(matches.map((m) => m.purl)).toEqual(['pkg:npm/a@1.0.0']);
  });

  test('an advisory shared by many packages is downloaded once', async () => {
    const purls = ['a', 'b', 'c', 'd', 'e'].map((n) => `pkg:npm/${n}@1.0.0`);
    const { fake, client } = setup({
      vulnsByPurl: Object.fromEntries(purls.map((p) => [p, [{ id: 'SHARED', modified: 'm1' }]])),
      records: { SHARED: record('SHARED') },
    });
    const { matches, stats } = await lookupVulnerabilities(purls.map(component), { client, cache: createMemoryCache() });
    expect(fake.calls.filter((c) => c.method === 'GET')).toHaveLength(1);
    expect(matches).toHaveLength(5);
    expect(matches.every((m) => m.records[0].id === 'SHARED')).toBe(true);
    expect(stats.advisories).toBe(1);
  });

  test('never runs more than 8 downloads at once', async () => {
    const idsList = Array.from({ length: 40 }, (_, i) => `ID-${i}`);
    const { fake, client } = setup({
      vulnsByPurl: { 'pkg:npm/big@1.0.0': idsList.map((id) => ({ id, modified: 'm1' })) },
      records: Object.fromEntries(idsList.map((id) => [id, record(id)])),
    });
    const { stats } = await lookupVulnerabilities([component('pkg:npm/big@1.0.0')], { client, cache: createMemoryCache() });
    expect(stats.fetched).toBe(40);
    expect(fake.maxInFlight()).toBeLessThanOrEqual(8);
    expect(fake.maxInFlight()).toBeGreaterThan(1);
  });

  test('a second scan uses the cache; a changed advisory is fetched again', async () => {
    const cache = createMemoryCache();
    const data = { vulnsByPurl: { 'pkg:npm/a@1.0.0': [{ id: 'X', modified: 'm1' }, { id: 'Y', modified: 'm1' }] }, records: { X: record('X'), Y: record('Y') } };
    let { client } = setup(data);
    const first = await lookupVulnerabilities([component('pkg:npm/a@1.0.0')], { client, cache });
    expect(first.stats).toMatchObject({ fetched: 2, fromCache: 0 });

    ({ client } = setup(data));
    const second = await lookupVulnerabilities([component('pkg:npm/a@1.0.0')], { client, cache });
    expect(second.stats).toMatchObject({ fetched: 0, fromCache: 2 });

    data.vulnsByPurl['pkg:npm/a@1.0.0'][0].modified = 'm2';    // OSV updated advisory X
    ({ client } = setup(data));
    const third = await lookupVulnerabilities([component('pkg:npm/a@1.0.0')], { client, cache });
    expect(third.stats).toMatchObject({ fetched: 1, fromCache: 1 });
  });

  test('withdrawn advisories are dropped and counted', async () => {
    const { client } = setup({
      vulnsByPurl: { 'pkg:npm/a@1.0.0': [{ id: 'OLD', modified: 'm1' }, { id: 'REAL', modified: 'm1' }] },
      records: { OLD: record('OLD', { withdrawn: '2024-01-01T00:00:00Z' }), REAL: record('REAL') },
    });
    const { matches, stats } = await lookupVulnerabilities([component('pkg:npm/a@1.0.0')], { client, cache: createMemoryCache() });
    expect(matches[0].records.map((r) => r.id)).toEqual(['REAL']);
    expect(stats).toMatchObject({ withdrawn: 1, advisories: 1 });
  });

  test('a package whose only advisory was withdrawn is not a match', async () => {
    const { client } = setup({
      vulnsByPurl: { 'pkg:npm/a@1.0.0': [{ id: 'OLD', modified: 'm1' }] },
      records: { OLD: record('OLD', { withdrawn: '2024-01-01T00:00:00Z' }) },
    });
    const { matches } = await lookupVulnerabilities([component('pkg:npm/a@1.0.0')], { client, cache: createMemoryCache() });
    expect(matches).toEqual([]);
  });

  test('an advisory OSV can no longer find (404) becomes a warning', async () => {
    const { client } = setup({
      vulnsByPurl: { 'pkg:npm/a@1.0.0': [{ id: 'GONE', modified: 'm1' }, { id: 'REAL', modified: 'm1' }] },
      records: { REAL: record('REAL') },
    });
    const { matches, warnings, stats } = await lookupVulnerabilities([component('pkg:npm/a@1.0.0')], { client, cache: createMemoryCache() });
    expect(matches[0].records.map((r) => r.id)).toEqual(['REAL']);
    expect(warnings).toEqual(['OSV.dev no longer has 1 advisory it listed, so it was skipped: GONE']);
    expect(stats.missing).toBe(1);
  });

  test('if OSV.dev stays down, the lookup fails instead of reporting "no vulnerabilities"', async () => {
    const fake = fakeFetch(() => ({ status: 503 }));
    const client = createOsvClient({ fetch: fake.fetch, sleep: () => Promise.resolve() });
    await expect(lookupVulnerabilities([component('pkg:npm/a@1.0.0')], { client, cache: createMemoryCache() }))
      .rejects.toMatchObject({ name: 'OsvError', code: 'OSV_UNAVAILABLE' });
  });

  test('an unusable record is OSV_BAD_RESPONSE', async () => {
    const { client } = setup({ vulnsByPurl: { 'pkg:npm/a@1.0.0': [{ id: 'X', modified: 'm1' }] }, records: { X: { summary: 'no id' } } });
    await expect(lookupVulnerabilities([component('pkg:npm/a@1.0.0')], { client, cache: createMemoryCache() }))
      .rejects.toMatchObject({ code: 'OSV_BAD_RESPONSE' });
  });

  test('an empty SBOM makes no requests', async () => {
    const { fake, client } = setup({});
    const { matches, stats } = await lookupVulnerabilities([], { client, cache: createMemoryCache() });
    expect(matches).toEqual([]);
    expect(stats.queried).toBe(0);
    expect(fake.calls).toEqual([]);
  });
});

describe('createMemoryCache', () => {
  test('drops the oldest entry when full', async () => {
    const cache = createMemoryCache({ maxEntries: 2 });
    await cache.set('a', 1);
    await cache.set('b', 2);
    await cache.set('c', 3);
    expect(await cache.get('a')).toBeUndefined();
    expect(await cache.get('c')).toBe(3);
    expect(cache.size).toBe(2);
  });
});

const network = process.env.NETWORK_TESTS === '1' ? describe : describe.skip;

network('lookupVulnerabilities against the real OSV.dev', () => {
  jest.setTimeout(60_000);
  test('lodash@4.17.11 has the defaultsDeep prototype pollution advisory', async () => {
    const { matches } = await lookupVulnerabilities([component('pkg:npm/lodash@4.17.11')], { cache: createMemoryCache() });
    const rec = matches[0].records.find((r) => r.id === 'GHSA-jf85-cpcp-j695');
    expect(rec.aliases).toContain('CVE-2019-10744');
  });
});
