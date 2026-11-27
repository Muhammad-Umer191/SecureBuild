const { pypiPurl, normalizePypiName } = require('../../../../src/services/ecosystems/pypi/names');

describe('PyPI names', () => {
  test.each([
    ['requests', 'requests'],
    ['Flask_Login', 'flask-login'],
    ['zope.interface', 'zope-interface'],
    ['Foo__Bar--baz', 'foo-bar-baz'],
  ])('%s -> %s', (name, normalized) => {
    expect(normalizePypiName(name)).toBe(normalized);
  });
});

describe('PyPI purls', () => {
  test.each([
    ['requests', '2.31.0', 'pkg:pypi/requests@2.31.0'],
    ['Flask_Login', '0.6.2', 'pkg:pypi/flask-login@0.6.2'],
    ['django', '4.2rc1', 'pkg:pypi/django@4.2rc1'],
    ['torch', '2.1.0+cpu', 'pkg:pypi/torch@2.1.0%2Bcpu'],
  ])('%s@%s -> %s', (name, version, purl) => {
    expect(pypiPurl(name, version)).toBe(purl);
  });
});
