const { toCycloneDX } = require('../../../src/services/cyclonedx');
const { scan } = require('../../../src/services/scan');
const { createMemoryCache } = require('../../../src/services/osv');
const { removeRepo } = require('../helpers');
const { validateBom } = require('./validateBom');
const { SHA, fakeWithClone, fakeOsvClient, fixtureRepo } = require('../scan/fakes');

const SERIAL = 'urn:uuid:00000000-0000-4000-8000-000000000000';

// A hand-made ScanResult for the edge cases.
const comp = (name, version, extra = {}) => ({
  name, version, ecosystem: 'npm', purl: `pkg:npm/${name.replace('@', '%40')}@${version}`,
  direct: false, dev: false, license: null, dependsOn: [], source: 'package-lock.json', approximate: false, ...extra,
});
const finding = (purl, ids, extra = {}) => ({
  purl, vulnIds: ids, cves: ids.filter((i) => i.startsWith('CVE-')), summary: `about ${ids[0]}`,
  references: [`https://github.com/advisories/${ids[0]}`], cvss: {}, score: null, severity: 'UNKNOWN',
  fixedVersion: null, approximate: false, ...extra,
});
const result = (components, findings) => ({
  repoUrl: 'https://github.com/acme/app', commitSha: SHA, scannedAt: '2026-11-27T10:00:00.000Z',
  components, findings, upgrades: [], warnings: [], stats: {},
});

const LODASH_V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H';

const edgeCases = result(
  [
    comp('lodash', '4.17.11', { direct: true, license: 'MIT', dependsOn: ['pkg:npm/debug@2.6.9'] }),
    comp('debug', '2.6.9', { license: '(MIT OR Apache-2.0)' }),
    comp('@babel/core', '7.0.0', { direct: true, dev: true, license: 'SEE LICENSE IN LICENSE.md' }),
    comp('fsevents', '1.2.9', { license: 'mit' }),
    comp('guessed', '1.0.0', { direct: true, approximate: true, source: 'web/package.json' }),
  ],
  [
    finding('pkg:npm/fsevents@1.2.9', ['MAL-2023-462', 'GHSA-xv2f-5jw4-v95m'], { severity: 'CRITICAL', fixedVersion: '1.2.11' }),
    finding('pkg:npm/lodash@4.17.11', ['GHSA-jf85-cpcp-j695', 'CVE-2019-10744', 'SNYK-JS-LODASH-450202'], {
      cvss: { v31: { vector: LODASH_V31, score: 9.1 } }, score: 9.1, severity: 'CRITICAL', fixedVersion: '4.17.12',
    }),
    finding('pkg:npm/debug@2.6.9', ['GHSA-shared'], {
      cvss: { v31: { vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', score: 9.1 } }, score: 9.1, severity: 'CRITICAL', fixedVersion: '2.6.10',
    }),
    finding('pkg:npm/%40babel/core@7.0.0', ['GHSA-shared'], {
      cvss: { v31: { vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', score: 9.1 } }, score: 9.1, severity: 'CRITICAL',
    }),
    finding('pkg:npm/guessed@1.0.0', ['GHSA-label-only'], { severity: 'MEDIUM', approximate: true }),
    finding('pkg:npm/guessed@1.0.0', ['PYSEC-nothing']),
  ],
);

describe('toCycloneDX passes the official CycloneDX 1.5 schema', () => {
  let root;
  afterEach(() => root && removeRepo(root));

  test('a real scan() result (npm + PyPI fixtures, 2 findings)', async () => {
    root = await fixtureRepo();
    const scanned = await scan('https://github.com/acme/app', {
      withClone: fakeWithClone(root), osvClient: fakeOsvClient(), cache: createMemoryCache(),
    });
    const bom = toCycloneDX(scanned);
    expect(validateBom(bom)).toEqual([]);
    expect(bom.components).toHaveLength(18);
    expect(bom.vulnerabilities.map((v) => v.id)).toEqual(['GHSA-r5fr-rjxr-66jc', 'GHSA-xxjr-mmjv-4gpg']);
  });

  test('the edge cases (malware, odd licenses, scoped purl, CVSS 3.0, shared advisory, approximate, unknown)', () => {
    expect(validateBom(toCycloneDX(edgeCases))).toEqual([]);
  });

  test('an empty repo', () => {
    expect(validateBom(toCycloneDX(result([], [])))).toEqual([]);
  });

  test('the validator really runs: a broken BOM is reported', () => {
    const bom = toCycloneDX(edgeCases);
    bom.components[0].scope = 'dev';
    expect(validateBom(bom)).toEqual([
      '/components/0/scope must be equal to one of the allowed values (required, optional, excluded)',
    ]);
  });
});

describe('toCycloneDX mapping', () => {
  const bom = toCycloneDX(edgeCases, { serialNumber: SERIAL, toolVersion: '9.9.9' });

  test('header and metadata describe the scanned repo and the tool', () => {
    expect(bom).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: SERIAL, version: 1 });
    expect(bom.metadata).toEqual({
      timestamp: '2026-11-27T10:00:00.000Z',
      tools: { components: [{ type: 'application', name: 'SecureBuild Scanner', version: '9.9.9' }] },
      component: {
        type: 'application',
        'bom-ref': 'https://github.com/acme/app',
        name: 'acme/app',
        version: SHA,
        externalReferences: [{ type: 'vcs', url: 'https://github.com/acme/app' }],
      },
    });
  });

  test('a component has purl, scope, license and SecureBuild properties', () => {
    expect(bom.components.find((c) => c.name === '@babel/core')).toEqual({
      type: 'library',
      'bom-ref': 'pkg:npm/%40babel/core@7.0.0',
      name: '@babel/core',
      version: '7.0.0',
      purl: 'pkg:npm/%40babel/core@7.0.0',
      scope: 'optional',                                           // dev dependency
      licenses: [{ license: { name: 'SEE LICENSE IN LICENSE.md' } }],
      properties: [{ name: 'securebuild:source', value: 'package-lock.json' }],
    });
    expect(bom.components.find((c) => c.name === 'guessed').properties).toContainEqual({ name: 'securebuild:approximate', value: 'true' });
  });

  test.each([
    ['lodash', [{ license: { id: 'MIT' } }]],
    ['fsevents', [{ license: { id: 'MIT' } }]],                   // "mit" -> canonical "MIT"
    ['debug', [{ expression: '(MIT OR Apache-2.0)' }]],
    ['guessed', undefined],                                        // no license -> no field
  ])('license of %s', (name, licenses) => {
    expect(bom.components.find((c) => c.name === name).licenses).toEqual(licenses);
  });

  test('dependencies: repo -> direct packages; approximate packages have no entry', () => {
    expect(bom.dependencies).toEqual([
      { ref: 'https://github.com/acme/app', dependsOn: ['pkg:npm/%40babel/core@7.0.0', 'pkg:npm/guessed@1.0.0', 'pkg:npm/lodash@4.17.11'] },
      { ref: 'pkg:npm/%40babel/core@7.0.0', dependsOn: [] },
      { ref: 'pkg:npm/debug@2.6.9', dependsOn: [] },
      { ref: 'pkg:npm/fsevents@1.2.9', dependsOn: [] },
      { ref: 'pkg:npm/lodash@4.17.11', dependsOn: ['pkg:npm/debug@2.6.9'] },
    ]);
  });

  test('components and dependencies are sorted by purl; output is reproducible', () => {
    expect(bom.components.map((c) => c.purl)).toEqual([...bom.components.map((c) => c.purl)].sort());
    expect(toCycloneDX(edgeCases, { serialNumber: SERIAL, toolVersion: '9.9.9' })).toEqual(bom);
  });
});

describe('toCycloneDX vulnerabilities', () => {
  const bom = toCycloneDX(edgeCases, { serialNumber: SERIAL });
  const vuln = (id) => bom.vulnerabilities.find((v) => v.id === id);

  test('a CVSS 3.1 finding: rating, aliases with sources, advisory, fix, affected version', () => {
    expect(vuln('GHSA-jf85-cpcp-j695')).toEqual({
      'bom-ref': 'GHSA-jf85-cpcp-j695',
      id: 'GHSA-jf85-cpcp-j695',
      source: { name: 'OSV', url: 'https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695' },
      references: [
        { id: 'CVE-2019-10744', source: { name: 'NVD', url: 'https://nvd.nist.gov/vuln/detail/CVE-2019-10744' } },
        { id: 'SNYK-JS-LODASH-450202', source: { name: 'OSV', url: 'https://osv.dev/vulnerability/SNYK-JS-LODASH-450202' } },
      ],
      ratings: [{
        source: { name: 'OSV', url: 'https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695' },
        score: 9.1, severity: 'critical', method: 'CVSSv31', vector: LODASH_V31,
      }],
      description: 'about GHSA-jf85-cpcp-j695',
      recommendation: 'pkg:npm/lodash@4.17.11: upgrade to 4.17.12',
      advisories: [{ url: 'https://github.com/advisories/GHSA-jf85-cpcp-j695' }],
      affects: [{ ref: 'pkg:npm/lodash@4.17.11', versions: [{ version: '4.17.11', status: 'affected' }] }],
    });
  });

  test('one advisory on two packages is one entry with two affects; CVSS 3.0 -> CVSSv3', () => {
    const v = vuln('GHSA-shared');
    expect(v.affects.map((a) => a.ref)).toEqual(['pkg:npm/debug@2.6.9', 'pkg:npm/%40babel/core@7.0.0']);
    expect(v.recommendation).toBe('pkg:npm/debug@2.6.9: upgrade to 2.6.10\npkg:npm/%40babel/core@7.0.0: no fixed version known');
    expect(v.ratings[0].method).toBe('CVSSv3');
    expect(bom.vulnerabilities.filter((x) => x.id === 'GHSA-shared')).toHaveLength(1);
  });

  test('flaws are listed in the same order as the findings (malware first)', () => {
    expect(bom.vulnerabilities.map((v) => v.id)).toEqual([
      'MAL-2023-462', 'GHSA-jf85-cpcp-j695', 'GHSA-shared', 'GHSA-label-only', 'PYSEC-nothing',
    ]);
  });

  test('malware gets a critical "other" rating', () => {
    expect(vuln('MAL-2023-462').ratings).toEqual([expect.objectContaining({ severity: 'critical', method: 'other' })]);
    expect(vuln('MAL-2023-462').references[0]).toEqual({
      id: 'GHSA-xv2f-5jw4-v95m', source: { name: 'GitHub Advisory Database', url: 'https://github.com/advisories/GHSA-xv2f-5jw4-v95m' },
    });
  });

  test('a label-only severity becomes an "other" rating; approximate is marked', () => {
    expect(vuln('GHSA-label-only').ratings).toEqual([expect.objectContaining({ severity: 'medium', method: 'other' })]);
    expect(vuln('GHSA-label-only').properties).toEqual([{ name: 'securebuild:approximate', value: 'true' }]);
  });

  test('UNKNOWN severity has no rating', () => {
    expect(vuln('PYSEC-nothing').ratings).toEqual([]);
  });
});
