// Contract-shaped fixtures shared by tests.
export function makeFinding(overrides = {}) {
  return {
    id: '6651000000000000000000aa',
    vulnId: 'GHSA-hrpp-h998-j3pp',
    cveIds: ['CVE-2022-24999'],
    summary: 'qs vulnerable to Prototype Pollution',
    package: { name: 'qs', version: '6.5.2', ecosystem: 'npm', purl: 'pkg:npm/qs@6.5.2' },
    direct: false,
    severity: 'high',
    score: 7.5,
    hasFix: true,
    recommendedFix: '6.10.3',
    status: 'open',
    published: '2022-11-26T00:00:00.000Z',
    aliases: ['CVE-2022-24999'],
    details: 'Line one of advisory.\nLine two <b>not bold</b>',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    scoreSource: 'osv',
    fixedVersions: ['6.2.4', '6.10.3'],
    dependencyPath: ['express@4.17.1', 'body-parser@1.19.0', 'qs@6.5.2'],
    references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-hrpp-h998-j3pp' }],
    cwes: ['CWE-1321'],
    modified: '2024-01-02T00:00:00.000Z',
    firstSeenAt: '2026-11-01T10:00:00.000Z',
    ignore: null,
    cves: [
      {
        cveId: 'CVE-2022-24999', state: 'PUBLISHED', score: 7.5, severity: 'high', cvssVersion: '3.1',
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', source: 'CISA-ADP',
        description: 'qs before 6.10.3 allows a hang.', published: '2022-11-26T00:00:00.000Z',
        url: 'https://www.cve.org/CVERecord?id=CVE-2022-24999',
      },
    ],
    scoring: {
      explanation: 'Score 7.5 (CVSS 3.1) taken from OSV advisory; severity band high = 7.0-8.9',
      thresholds: { critical: 9.0, high: 7.0, medium: 4.0, low: 0.1 },
    },
    ...overrides,
  };
}

export function makeComponent(i, overrides = {}) {
  return {
    id: `6652${String(i).padStart(20, '0')}`,
    name: `pkg-${i}`,
    version: '1.0.0',
    ecosystem: 'npm',
    purl: `pkg:npm/pkg-${i}@1.0.0`,
    direct: i % 2 === 0,
    licenses: ['MIT'],
    vulnerabilityCount: 0,
    maxSeverity: null,
    ...overrides,
  };
}

export function makeComponentsResponse(items, overrides = {}) {
  return {
    scan: { id: '6650aaaa', finishedAt: '2026-11-10T09:12:00.000Z', commitSha: 'a1b2c3d' },
    items,
    page: 1,
    limit: 20,
    total: items.length,
    summary: { total: 312, direct: 18, transitive: 294, vulnerable: 7, byEcosystem: { npm: 300, PyPI: 12 } },
    ...overrides,
  };
}
