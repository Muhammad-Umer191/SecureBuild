const { pypiLowest } = require('../../../../src/services/ecosystems/pypi/versions');

describe('pypiLowest', () => {
  test.each([
    ['==2.31.0', { version: '2.31.0' }],
    ['>=2.0,<3', { version: '2.0' }],
    ['>= 2.0, < 3', { version: '2.0' }],
    ['~=1.4.2', { version: '1.4.2' }],
    ['^1.2', { version: '1.2' }],             // Poetry caret
    ['~1.2', { version: '1.2' }],             // Poetry tilde
    ['1.2.3', { version: '1.2.3' }],          // Poetry bare version = exact
    ['==1.2.*', { version: '1.2' }],
    ['>=1.0,>=1.5', { version: '1.5' }],      // highest lower bound wins
    ['^1.2 || ^2.0', { version: '1.2' }],     // Poetry "or": lowest alternative
    ['>=2.0rc1', { version: '2.0rc1' }],
    [null, { reason: 'unbounded' }],
    ['*', { reason: 'unbounded' }],
    ['<3', { reason: 'unbounded' }],
    ['>2.0', { reason: 'unbounded' }],
    ['!=1.0', { reason: 'unbounded' }],
    ['banana', { reason: 'invalid' }],
  ])('%p -> %p', (spec, expected) => {
    expect(pypiLowest(spec)).toEqual(expected);
  });
});
