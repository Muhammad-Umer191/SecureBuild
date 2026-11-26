const { npmLowest } = require('../../../../src/services/ecosystems/npm/versions');

describe('npmLowest', () => {
  test.each([
    ['^4.17.0', { version: '4.17.0' }],
    ['~1.2.3', { version: '1.2.3' }],
    ['>=2 <3', { version: '2.0.0' }],
    ['1.x', { version: '1.0.0' }],
    ['4.17.21', { version: '4.17.21' }],
    ['>1.2.3', { version: '1.2.4' }],
    ['^0.0.0', { version: '0.0.0' }],
    ['*', { reason: 'unbounded' }],
    ['', { reason: 'unbounded' }],
    ['latest', { reason: 'unbounded' }],
    ['<2', { reason: 'unbounded' }],
    ['next', { reason: 'invalid' }],
    ['git+https://github.com/a/b.git', { reason: 'nonRegistry' }],
    ['github:a/b', { reason: 'nonRegistry' }],
    ['a/b', { reason: 'nonRegistry' }],
    ['file:../x', { reason: 'nonRegistry' }],
    ['workspace:*', { reason: 'nonRegistry' }],
    ['npm:lodash@^4', { reason: 'nonRegistry' }],
    [42, { reason: 'invalid' }],
  ])('%p -> %p', (range, expected) => {
    expect(npmLowest(range)).toEqual(expected);
  });
});
