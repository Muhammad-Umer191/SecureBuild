const { parsePackageJson } = require('../../../../src/services/ecosystems/npm/manifest');
const { ParseError } = require('../../../../src/services/common/errors');

const summary = (components) => components.map((c) => `${c.name}@${c.version}${c.dev ? ' (dev)' : ''}`);

describe('package.json fallback', () => {
  const { components, warnings } = parsePackageJson({
    dependencies: { express: '^4.17.1', 'left-pad': '*', mine: 'github:me/mine', local: 'file:../local' },
    optionalDependencies: { fsevents: '~2.3.2' },
    devDependencies: { jest: '>=29 <30', weird: 'next' },
  }, { source: 'web/package.json' });

  test('estimates the lowest version of each range', () => {
    expect(summary(components)).toEqual(['express@4.17.1', 'fsevents@2.3.2', 'jest@29.0.0 (dev)']);
  });

  test('marks everything as direct and approximate, with no dependency links', () => {
    expect(components.every((c) => c.direct && c.approximate && c.dependsOn.length === 0 && c.source === 'web/package.json')).toBe(true);
  });

  test('explains what was skipped', () => {
    expect(warnings).toEqual([
      'web/package.json: skipped 2 dependencies not from the registry (git, file, link or URL): mine, local',
      'web/package.json: skipped 1 dependency with no minimum version, so the installed version cannot be estimated: left-pad',
      'web/package.json: skipped 1 dependency with a version we could not read: weird',
    ]);
  });

  test('a non-object package.json raises ParseError', () => {
    expect(() => parsePackageJson([], { source: 'package.json' })).toThrow(ParseError);
  });
});
