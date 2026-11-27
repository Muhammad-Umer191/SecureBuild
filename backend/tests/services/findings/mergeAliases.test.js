const { mergeAliases } = require('../../../src/services/findings/mergeAliases');

const rec = (id, aliases = [], extra = {}) => ({ id, aliases, ...extra });

describe('mergeAliases', () => {
  test('a GHSA and a PYSEC record for the same CVE become one group', () => {
    const groups = mergeAliases([
      rec('PYSEC-2021-98', ['CVE-2021-33203', 'GHSA-68w8-qjq3-2gfm']),
      rec('GHSA-68w8-qjq3-2gfm', ['CVE-2021-33203']),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].vulnIds).toEqual(['GHSA-68w8-qjq3-2gfm', 'PYSEC-2021-98', 'CVE-2021-33203']);
    expect(groups[0].cves).toEqual(['CVE-2021-33203']);
  });

  test('chains are followed: A lists B, B lists C', () => {
    const groups = mergeAliases([rec('A', ['B']), rec('C', ['B']), rec('D')]);
    expect(groups.map((g) => g.vulnIds)).toEqual([['A', 'C', 'B'], ['D']]);
  });

  test('records sharing only a CVE are joined, unrelated ones stay apart', () => {
    const groups = mergeAliases([
      rec('GHSA-1', ['CVE-1']), rec('PYSEC-1', ['CVE-1']), rec('GHSA-2', ['CVE-2']),
    ]);
    expect(groups.map((g) => g.vulnIds)).toEqual([['GHSA-1', 'PYSEC-1', 'CVE-1'], ['GHSA-2', 'CVE-2']]);
  });

  test('other aliases are listed after record IDs, CVEs first', () => {
    const [group] = mergeAliases([rec('GHSA-jf85-cpcp-j695', ['SNYK-JS-LODASH-450202', 'CVE-2019-10744'])]);
    expect(group.vulnIds).toEqual(['GHSA-jf85-cpcp-j695', 'CVE-2019-10744', 'SNYK-JS-LODASH-450202']);
  });

  test('summary prefers GHSA, then any summary, then the first line of details, then the ID', () => {
    expect(mergeAliases([rec('PYSEC-1', ['GHSA-1'], { summary: 'python text' }), rec('GHSA-1', [], { summary: 'github text' })])[0].summary)
      .toBe('github text');
    expect(mergeAliases([rec('PYSEC-1', [], { details: 'First line.\nMore detail.' })])[0].summary).toBe('First line.');
    expect(mergeAliases([rec('PYSEC-1')])[0].summary).toBe('PYSEC-1');
  });

  test('references are combined without duplicates', () => {
    const [group] = mergeAliases([
      rec('GHSA-1', ['PYSEC-1'], { references: [{ url: 'https://a' }, { url: 'https://b' }] }),
      rec('PYSEC-1', [], { references: [{ url: 'https://b' }, { url: 'https://c' }, { nope: 1 }] }),
    ]);
    expect(group.references).toEqual(['https://a', 'https://b', 'https://c']);
  });
});
