const { buildFindings } = require('../../../src/services/findings');
const { realFixtures } = require('../osv/fakeOsv');

// The real OSV records saved in tests/services/osv/fixtures. Expected values
// were worked out by hand from those files (fix per range) and with the
// independent Python `cvss` package (scores).
const { vulnsByPurl, records } = realFixtures();
const matchesFor = (purl) => ({ purl, records: vulnsByPurl[purl].map((v) => records[v.id]) });

const lodash = { name: 'lodash', version: '4.17.11', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.11', approximate: false };
const babel = { name: '@babel/traverse', version: '7.0.0', ecosystem: 'npm', purl: 'pkg:npm/%40babel/traverse@7.0.0', approximate: true };

describe('buildFindings on real OSV records', () => {
  const { findings, upgrades, warnings, stats } = buildFindings(
    [lodash, babel],
    [matchesFor(lodash.purl), matchesFor(babel.purl)],
  );
  const row = (f) => [f.vulnIds[0], f.score, f.severity, f.fixedVersion];

  test('one finding per advisory, scored, with its own fix, worst first', () => {
    expect(findings.map(row)).toEqual([
      ['GHSA-67hx-6x53-jw92', 9.3, 'CRITICAL', '7.23.2'],     // @babel/traverse
      ['GHSA-jf85-cpcp-j695', 9.1, 'CRITICAL', '4.17.12'],
      ['GHSA-r5fr-rjxr-66jc', 8.1, 'HIGH', '4.18.0'],
      ['GHSA-p6mc-m468-83gw', 7.4, 'HIGH', '4.17.19'],
      ['GHSA-35jh-r3h4-6jhm', 7.2, 'HIGH', '4.17.21'],
      ['GHSA-xxjr-mmjv-4gpg', 6.9, 'MEDIUM', '4.17.23'],     // v4.0 6.9 beats v3.1 6.5
      ['GHSA-29mw-wpgm-hmr9', 5.3, 'MEDIUM', '4.17.21'],
    ]);
  });

  test('a finding carries its CVEs, vectors and references', () => {
    const f = findings.find((x) => x.vulnIds[0] === 'GHSA-jf85-cpcp-j695');
    expect(f.cves).toEqual(['CVE-2019-10744']);
    expect(f.vulnIds).toEqual(['GHSA-jf85-cpcp-j695', 'CVE-2019-10744', 'SNYK-JS-LODASH-450202']);
    expect(f.cvss).toEqual({ v31: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', score: 9.1 } });
    expect(f.summary).toBe('Prototype Pollution in lodash');
    expect(f.references.length).toBeGreaterThan(0);
    expect(f.purl).toBe('pkg:npm/lodash@4.17.11');
  });

  test('both CVSS versions are kept when an advisory has both', () => {
    const f = findings.find((x) => x.vulnIds[0] === 'GHSA-xxjr-mmjv-4gpg');
    expect(Object.keys(f.cvss)).toEqual(['v31', 'v40']);
    expect([f.cvss.v31.score, f.cvss.v40.score]).toEqual([6.5, 6.9]);
  });

  test('one upgrade per package closes all of its findings', () => {
    expect(upgrades).toEqual([
      { purl: 'pkg:npm/lodash@4.17.11', name: 'lodash', ecosystem: 'npm', from: '4.17.11', to: '4.18.0', closes: 6, unfixed: 0, worstSeverity: 'CRITICAL' },
      { purl: 'pkg:npm/%40babel/traverse@7.0.0', name: '@babel/traverse', ecosystem: 'npm', from: '7.0.0', to: '7.23.2', closes: 1, unfixed: 0, worstSeverity: 'CRITICAL' },
    ]);
  });

  test('approximate is copied from the component', () => {
    expect(findings.filter((f) => f.approximate).map((f) => f.purl)).toEqual(['pkg:npm/%40babel/traverse@7.0.0']);
  });

  test('stats and no warnings', () => {
    expect(stats).toEqual({
      findings: 7, packages: 2, advisoryRecords: 7, mergedAway: 0, fixable: 7,
      bySeverity: { CRITICAL: 2, HIGH: 3, MEDIUM: 2, LOW: 0, NONE: 0, UNKNOWN: 0 },
    });
    expect(warnings).toEqual([]);
  });
});

describe('buildFindings merging', () => {
  test('alias records on one package become one finding', () => {
    const django = { name: 'django', version: '3.2.0', ecosystem: 'PyPI', purl: 'pkg:pypi/django@3.2.0', approximate: false };
    const ranges = [{ type: 'ECOSYSTEM', events: [{ introduced: '3.2' }, { fixed: '3.2.4' }] }];
    const affected = [{ package: { name: 'Django', ecosystem: 'PyPI' }, ranges }];
    const { findings, stats } = buildFindings([django], [{
      purl: django.purl,
      records: [
        { id: 'GHSA-68w8-qjq3-2gfm', aliases: ['CVE-2021-33203'], summary: 'Django path traversal', affected,
          severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N' }] },
        { id: 'PYSEC-2021-98', aliases: ['CVE-2021-33203', 'GHSA-68w8-qjq3-2gfm'], details: 'Django before ...', affected },
      ],
    }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      vulnIds: ['GHSA-68w8-qjq3-2gfm', 'PYSEC-2021-98', 'CVE-2021-33203'],
      cves: ['CVE-2021-33203'],
      summary: 'Django path traversal',
      score: 4.9,
      severity: 'MEDIUM',
      fixedVersion: '3.2.4',
    });
    expect(stats.mergedAway).toBe(1);
  });

  test('malware is CRITICAL and listed before scored critical bugs', () => {
    const fsevents = { name: 'fsevents', version: '1.2.9', ecosystem: 'npm', purl: 'pkg:npm/fsevents@1.2.9', approximate: false };
    const affected = [{ package: { name: 'fsevents', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.11' }] }] }];
    const { findings, upgrades } = buildFindings([fsevents], [{
      purl: fsevents.purl,
      records: [
        { id: 'GHSA-8r6j-v8pm-fqw3', aliases: ['CVE-2023-45311'], summary: 'Code injection in fsevents', affected,
          severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] },
        { id: 'MAL-2023-462', aliases: ['GHSA-xv2f-5jw4-v95m'], summary: 'Malicious code in fsevents (npm)', affected },
      ],
    }]);
    expect(findings.map((f) => [f.vulnIds[0], f.severity, f.score])).toEqual([
      ['MAL-2023-462', 'CRITICAL', null],
      ['GHSA-8r6j-v8pm-fqw3', 'CRITICAL', 9.8],
    ]);
    expect(upgrades[0]).toMatchObject({ to: '1.2.11', closes: 2, worstSeverity: 'CRITICAL' });
  });

  test('no matches -> no findings', () => {
    expect(buildFindings([lodash], [])).toMatchObject({ findings: [], upgrades: [], warnings: [] });
  });
});
