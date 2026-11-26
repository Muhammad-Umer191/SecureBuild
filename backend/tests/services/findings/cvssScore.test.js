const { scoreVector, scoreRecords, severityFromScore } = require('../../../src/services/findings/cvssScore');

// Expected scores were cross-checked with the independent Python `cvss` package.
describe('scoreVector', () => {
  test.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', { version: 'v31', score: 9.1 }],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L', { version: 'v31', score: 6.5 }],
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', { version: 'v31', score: 9.1 }],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:H/SI:H/SA:H/E:P', { version: 'v40', score: 6.9 }],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H', { version: 'v40', score: 10 }],
  ])('%s', (vector, expected) => {
    expect(scoreVector(vector)).toEqual(expected);
  });

  test.each([
    ['garbage', 'CVSS:3.1/AV:X/nonsense'],
    ['wrong version prefix', 'CVSS:3.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'],
    ['CVSS 2', 'AV:N/AC:L/Au:N/C:P/I:P/A:P'],
    ['not a string', 42],
  ])('%s -> null', (_label, vector) => {
    expect(scoreVector(vector)).toBeNull();
  });
});

describe('severityFromScore', () => {
  test.each([
    [10, 'CRITICAL'], [9.0, 'CRITICAL'], [8.9, 'HIGH'], [7.0, 'HIGH'], [6.9, 'MEDIUM'],
    [4.0, 'MEDIUM'], [3.9, 'LOW'], [0.1, 'LOW'], [0, 'NONE'], [null, 'UNKNOWN'],
  ])('%p -> %s', (score, severity) => {
    expect(severityFromScore(score)).toBe(severity);
  });
});

describe('scoreRecords', () => {
  const v3 = (score) => ({ type: 'CVSS_V3', score });
  const v4 = (score) => ({ type: 'CVSS_V4', score });

  test('keeps both versions and uses the highest score', () => {
    const result = scoreRecords([{
      id: 'GHSA-1',
      severity: [v3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L'), v4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:H/SI:H/SA:H/E:P')],
    }]);
    expect(result).toEqual({
      cvss: {
        v31: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L', score: 6.5 },
        v40: { vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:H/SI:H/SA:H/E:P', score: 6.9 },
      },
      score: 6.9,
      severity: 'MEDIUM',
      badVectors: [],
    });
  });

  test('across alias records, the highest v3 score wins', () => {
    const result = scoreRecords([
      { id: 'PYSEC-1', severity: [v3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L')] },
      { id: 'GHSA-1', severity: [v3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H')] },
    ]);
    expect(result.cvss.v31.score).toBe(9.1);
    expect(result.severity).toBe('CRITICAL');
  });

  test('without a vector, GitHub\'s label is used (MODERATE -> MEDIUM)', () => {
    const result = scoreRecords([{ id: 'GHSA-1', database_specific: { severity: 'MODERATE' } }]);
    expect(result).toEqual({ cvss: {}, score: null, severity: 'MEDIUM', badVectors: [] });
  });

  test('unexpected labels are ignored', () => {
    const result = scoreRecords([
      { id: 'A', database_specific: { severity: 'important' } },
      { id: 'B', database_specific: { severity: 'UNKNOWN' } },
      { id: 'C', database_specific: { severity: 42 } },
    ]);
    expect(result.severity).toBe('UNKNOWN');
  });

  test('labels are matched case-insensitively', () => {
    expect(scoreRecords([{ id: 'A', database_specific: { severity: 'high' } }]).severity).toBe('HIGH');
  });

  test('the worst label wins when records disagree', () => {
    const result = scoreRecords([
      { id: 'A', database_specific: { severity: 'LOW' } },
      { id: 'B', database_specific: { severity: 'HIGH' } },
    ]);
    expect(result.severity).toBe('HIGH');
  });

  test('malware (MAL- advisory) is CRITICAL even without a score', () => {
    expect(scoreRecords([{ id: 'MAL-2023-462' }])).toEqual({ cvss: {}, score: null, severity: 'CRITICAL', badVectors: [] });
  });

  test('malware is CRITICAL when only an alias is MAL-, and overrides a low CVSS score', () => {
    const result = scoreRecords([{
      id: 'GHSA-xv2f-5jw4-v95m',
      aliases: ['MAL-2023-462'],
      severity: [v3('CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N')],
    }]);
    expect(result.score).toBeLessThan(4);      // the vector alone would say LOW
    expect(result.severity).toBe('CRITICAL');
  });

  test('nothing at all -> UNKNOWN', () => {
    expect(scoreRecords([{ id: 'PYSEC-1' }])).toEqual({ cvss: {}, score: null, severity: 'UNKNOWN', badVectors: [] });
  });

  test('a malformed vector is reported and ignored', () => {
    const result = scoreRecords([{ id: 'GHSA-1', severity: [v3('CVSS:3.1/broken'), v3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H')] }]);
    expect(result.score).toBe(9.1);
    expect(result.badVectors).toEqual(['GHSA-1: CVSS:3.1/broken']);
  });
});
