const { parsePep508 } = require('../../../../src/services/ecosystems/pypi/pep508');

describe('parsePep508', () => {
  test.each([
    ['requests', { name: 'requests', extras: [], spec: null, url: null, marker: null }],
    ['requests>=2.0,<3', { name: 'requests', extras: [], spec: '>=2.0,<3', url: null, marker: null }],
    ['requests[socks,security] >= 2.0', { name: 'requests', extras: ['socks', 'security'], spec: '>= 2.0', url: null, marker: null }],
    ['Django (>=3.2)', { name: 'Django', extras: [], spec: '>=3.2', url: null, marker: null }],
    ['pywin32>=300 ; sys_platform == "win32"', { name: 'pywin32', extras: [], spec: '>=300', url: null, marker: 'sys_platform == "win32"' }],
    ['mylib @ https://example.com/mylib.zip', { name: 'mylib', extras: [], spec: null, url: 'https://example.com/mylib.zip', marker: null }],
  ])('%p', (text, expected) => {
    expect(parsePep508(text)).toEqual(expected);
  });

  test.each([[''], ['  '], ['>=1.0'], [null]])('rejects %p', (text) => {
    expect(parsePep508(text)).toBeNull();
  });
});
