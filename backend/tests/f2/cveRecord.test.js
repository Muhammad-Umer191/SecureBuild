// Unit tests: parsing cvelistV5 records and choosing the score (no network, no DB).
const log4j = require('./fixtures/CVE-2021-44228.json');
const qs = require('./fixtures/CVE-2022-24999.json');
const {
  CveRecordError, cveRecordPath, normalizeCveId, parseCveRecord, severityFromScore,
} = require('../../src/services/cve/cveRecord');

const record = (cna = {}, adp = [], meta = {}) => ({
  dataType: 'CVE_RECORD',
  cveMetadata: { cveId: 'CVE-2024-1234', state: 'PUBLISHED', datePublished: '2024-02-01T00:00:00Z', ...meta },
  containers: { cna: { descriptions: [{ lang: 'en', value: 'Example' }], ...cna }, adp },
});

describe('severityFromScore', () => {
  test.each([
    [10, 'critical'], [9.0, 'critical'], [8.9, 'high'], [7.0, 'high'],
    [6.9, 'medium'], [4.0, 'medium'], [3.9, 'low'], [0.1, 'low'], [0, 'none'],
  ])('%s -> %s', (score, sev) => expect(severityFromScore(score)).toBe(sev));

  test('CVSS v2 has no critical band', () => {
    expect(severityFromScore(10, '2.0')).toBe('high');
  });

  test.each([null, undefined, -1, 11, NaN, '7.5'])('invalid %p -> unknown', (s) => {
    expect(severityFromScore(s)).toBe('unknown');
  });
});

describe('normalizeCveId', () => {
  test('accepts and upper-cases valid ids', () => {
    expect(normalizeCveId('cve-2021-44228')).toBe('CVE-2021-44228');
    expect(normalizeCveId(' CVE-2024-1234567 ')).toBe('CVE-2024-1234567');
  });

  test.each([
    'CVE-2021-123', 'CVE-2021-12345678', 'CVE-1980-1234', 'CVE-2021-44228/../../etc/passwd',
    'CVE-2021-44228?x=1', '../CVE-2021-44228', 'GHSA-hrpp-h998-j3pp', '', null, { $ne: 1 },
  ])('rejects %p', (bad) => expect(normalizeCveId(bad)).toBeNull());
});

describe('cveRecordPath', () => {
  test.each([
    ['CVE-2021-44228', '2021/44xxx/CVE-2021-44228.json'],
    ['CVE-2024-0001', '2024/0xxx/CVE-2024-0001.json'],
    ['CVE-2023-1234', '2023/1xxx/CVE-2023-1234.json'],
    ['CVE-2024-1234567', '2024/1234xxx/CVE-2024-1234567.json'],
  ])('%s -> %s', (id, path) => expect(cveRecordPath(id)).toBe(path));
});

describe('parseCveRecord', () => {
  test('Log4Shell: CNA has only the word "critical", score comes from CISA-ADP', () => {
    const r = parseCveRecord(log4j, 'CVE-2021-44228');
    expect(r).toMatchObject({
      cveId: 'CVE-2021-44228', state: 'PUBLISHED', score: 10, severity: 'critical', cvssVersion: '3.1',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', source: 'CISA-ADP',
      url: 'https://www.cve.org/CVERecord?id=CVE-2021-44228',
    });
    expect(r.cwes).toContain('CWE-502');
    expect(r.description).toMatch(/Log4j2/);
  });

  test('qs: score and CWE only in the ADP container', () => {
    const r = parseCveRecord(qs, 'CVE-2022-24999');
    expect(r).toMatchObject({ score: 7.5, severity: 'high', source: 'CISA-ADP' });
    expect(r.cwes).toEqual(['CWE-1321']);
  });

  test('prefers the CNA over ADP, and CVSS 3.1 over 4.0', () => {
    const r = parseCveRecord(record(
      {
        providerMetadata: { shortName: 'GitHub_M' },
        metrics: [
          { cvssV4_0: { baseScore: 9.3, baseSeverity: 'CRITICAL', vectorString: 'CVSS:4.0/AV:N' } },
          { cvssV3_1: { baseScore: 8.1, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:N' } },
        ],
      },
      [{ providerMetadata: { shortName: 'CISA-ADP' }, metrics: [{ cvssV3_1: { baseScore: 5, vectorString: 'x' } }] }],
    ));
    expect(r).toMatchObject({ score: 8.1, severity: 'high', cvssVersion: '3.1', source: 'GitHub_M' });
  });

  test('uses CVSS 4.0 when it is the only block', () => {
    const r = parseCveRecord(record({ metrics: [{ cvssV4_0: { baseScore: 6.9, vectorString: 'CVSS:4.0/AV:N' } }] }));
    expect(r).toMatchObject({ score: 6.9, severity: 'medium', cvssVersion: '4.0', source: 'CNA' });
  });

  test('falls back to a text severity without a score', () => {
    const r = parseCveRecord(record({ metrics: [{ other: { type: 'unknown', content: { other: 'Moderate' } } }] }));
    expect(r).toMatchObject({ score: null, severity: 'medium' });
  });

  test('ignores out-of-range scores', () => {
    const r = parseCveRecord(record({ metrics: [{ cvssV3_1: { baseScore: 42 } }] }));
    expect(r).toMatchObject({ score: null, severity: 'unknown', source: null });
  });

  test('rejected CVEs get no score', () => {
    const r = parseCveRecord(record(
      { descriptions: undefined, rejectedReasons: [{ lang: 'en', value: 'Duplicate' }], metrics: [{ cvssV3_1: { baseScore: 9.8 } }] },
      [], { state: 'REJECTED' },
    ));
    expect(r).toMatchObject({ state: 'REJECTED', score: null, severity: 'unknown', description: 'Duplicate' });
  });

  test('rejects malformed records and id mismatches', () => {
    expect(() => parseCveRecord({ hello: 'world' })).toThrow(CveRecordError);
    expect(() => parseCveRecord(null)).toThrow(CveRecordError);
    expect(() => parseCveRecord(record(), 'CVE-2024-9999')).toThrow(CveRecordError);
  });

  test('caps very long descriptions', () => {
    const r = parseCveRecord(record({ descriptions: [{ lang: 'en', value: 'a'.repeat(10000) }] }));
    expect(r.description).toHaveLength(2000);
  });
});
