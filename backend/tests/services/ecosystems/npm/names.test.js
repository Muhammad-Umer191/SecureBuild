const { npmPurl, normalizeNpmName } = require('../../../../src/services/ecosystems/npm/names');

describe('npm purls', () => {
  test.each([
    ['express', '4.17.1', 'pkg:npm/express@4.17.1'],
    ['@babel/core', '7.0.0', 'pkg:npm/%40babel/core@7.0.0'],     // scope "@" encoded
    ['lodash.merge', '4.6.2', 'pkg:npm/lodash.merge@4.6.2'],
    ['react', '19.0.0-rc.1', 'pkg:npm/react@19.0.0-rc.1'],
    ['pkg', '1.0.0+build.5', 'pkg:npm/pkg@1.0.0%2Bbuild.5'],      // "+" encoded
  ])('%s@%s -> %s', (name, version, purl) => {
    expect(npmPurl(name, version)).toBe(purl);
  });

  test('names are kept as written', () => {
    expect(normalizeNpmName('JSONStream')).toBe('JSONStream');
  });
});
