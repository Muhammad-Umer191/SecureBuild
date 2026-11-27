// Offline: a local fixture repo stands in for the clone, and a fake OSV.dev
// replays real saved advisories. One network test runs with NETWORK_TESTS=1.
const { scan } = require('../../../src/services/scan');
const { CloneError } = require('../../../src/services/clone');
const { createOsvClient, createMemoryCache } = require('../../../src/services/osv');
const { makeRepo, removeRepo } = require('../helpers');
const { fakeFetch } = require('../osv/fakeOsv');
const fakes = require('./fakes');

const { SHA, fakeWithClone, fakeOsvClient } = fakes;

let root;
afterEach(() => root && removeRepo(root));

async function fixtureRepo(extra) {
  root = await fakes.fixtureRepo(extra);
  return root;
}

describe('scan', () => {
  test('runs the whole pipeline and returns a ScanResult', async () => {
    const log = [];
    const dir = await fixtureRepo();
    const result = await scan('https://github.com/acme/app', {
      withClone: fakeWithClone(dir, log), osvClient: fakeOsvClient(log), cache: createMemoryCache(),
    });

    expect(result).toMatchObject({ repoUrl: 'https://github.com/acme/app', commitSha: SHA });
    expect(new Date(result.scannedAt).toISOString()).toBe(result.scannedAt);
    expect(result.components).toHaveLength(18);                  // 11 npm + 7 PyPI
    expect(result.findings.map((f) => [f.vulnIds[0], f.severity, f.fixedVersion])).toEqual([
      ['GHSA-r5fr-rjxr-66jc', 'HIGH', '4.18.0'],
      ['GHSA-xxjr-mmjv-4gpg', 'MEDIUM', '4.17.23'],
    ]);
    expect(result.upgrades).toEqual([expect.objectContaining({ name: 'lodash', from: '4.17.21', to: '4.18.0', closes: 2 })]);
    expect(result.stats).toMatchObject({
      packages: 18, vulnerablePackages: 1, findings: 2, fixable: 2,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 0, NONE: 0, UNKNOWN: 0 },
    });
    expect(Object.keys(result.stats.durationMs)).toEqual(['clone', 'discover', 'parse', 'osv', 'findings', 'total']);
  });

  test('the clone is removed before OSV.dev is contacted', async () => {
    const log = [];
    const dir = await fixtureRepo();
    await scan('https://github.com/acme/app', { withClone: fakeWithClone(dir, log), osvClient: fakeOsvClient(log), cache: createMemoryCache() });
    expect(log.slice(0, 3)).toEqual(['cloned', 'clone removed', 'osv POST']);
  });

  test('reports progress once per stage, in order', async () => {
    const stages = [];
    const dir = await fixtureRepo();
    await scan('https://github.com/acme/app', {
      withClone: fakeWithClone(dir, []), osvClient: fakeOsvClient([]), cache: createMemoryCache(), onProgress: (s) => stages.push(s),
    });
    expect(stages).toEqual(['clone', 'discover', 'parse', 'osv', 'findings']);
  });

  test('collects warnings from every stage, in pipeline order', async () => {
    const dir = await fixtureRepo();
    const { warnings } = await scan('https://github.com/acme/app', {
      withClone: fakeWithClone(dir, []), osvClient: fakeOsvClient([]), cache: createMemoryCache(),
    });
    expect(warnings).toEqual([
      '1 dependency files inside test/example folders were skipped',                                     // discovery
      // parse: one per file, in discovery's order (sorted by path)
      'api/poetry.lock: skipped 1 dependency not from the registry (git, file, link or URL): mylib',
      'package-lock.json: skipped 1 dependency not from the registry (git, file, link or URL): gitdep',
    ]);
  });

  test('a repo without dependency files makes no OSV requests', async () => {
    const log = [];
    root = await makeRepo({ 'README.md': '# hi', 'main.go': 'package main' });
    const result = await scan('https://github.com/acme/empty', { withClone: fakeWithClone(root, log), osvClient: fakeOsvClient(log), cache: createMemoryCache() });
    expect(log).toEqual(['cloned', 'clone removed']);
    expect(result).toMatchObject({ components: [], findings: [], upgrades: [], stats: { packages: 0, findings: 0 } });
    expect(result.warnings[0]).toMatch(/^No dependency files found/);
  });
});

describe('scan errors', () => {
  test('a clone failure keeps its code and is labelled stage "clone"', async () => {
    const failingClone = async () => { throw new CloneError('REPO_NOT_FOUND', 'Repository not found or not public', { permanent: true }); };
    const err = await scan('https://github.com/acme/missing', { withClone: failingClone }).catch((e) => e);
    expect(err).toBeInstanceOf(CloneError);
    expect(err).toMatchObject({ code: 'REPO_NOT_FOUND', permanent: true, stage: 'clone' });
  });

  test('an invalid URL fails at clone without touching the network', async () => {
    await expect(scan('https://evil.com/a/b')).rejects.toMatchObject({ code: 'INVALID_URL', stage: 'clone' });
  });

  test('an OSV.dev outage fails the scan at stage "osv" (never a silent "no vulnerabilities")', async () => {
    const dir = await fixtureRepo();
    const down = createOsvClient({ fetch: fakeFetch(() => ({ status: 503 })).fetch, sleep: () => Promise.resolve() });
    const err = await scan('https://github.com/acme/app', { withClone: fakeWithClone(dir, []), osvClient: down, cache: createMemoryCache() }).catch((e) => e);
    expect(err).toMatchObject({ name: 'OsvError', code: 'OSV_UNAVAILABLE', stage: 'osv' });
  });

  test('an error inside discovery is labelled with that stage, not "clone"', async () => {
    const err = await scan('https://github.com/acme/app', { withClone: fakeWithClone('/definitely/not/here', []) }).catch((e) => e);
    expect(err.stage).toBe('discover');
  });
});

const network = process.env.NETWORK_TESTS === '1' ? describe : describe.skip;

network('scan against GitHub and OSV.dev', () => {
  jest.setTimeout(120_000);
  test('octocat/Hello-World: real clone, nothing to scan', async () => {
    const result = await scan('https://github.com/octocat/Hello-World', { cache: createMemoryCache() });
    expect(result.commitSha).toMatch(/^[0-9a-f]{40}$/);
    expect(result.components).toEqual([]);
    expect(result.warnings[0]).toMatch(/^No dependency files found/);
  });
});
