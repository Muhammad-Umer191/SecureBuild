const { parseNpmLockfile } = require('../../../../src/services/ecosystems/npm/lockfile');
const { ParseError } = require('../../../../src/services/common/errors');
const { json } = require('../../fixtures');

// "name@version" -> component, for readable assertions
const byKey = (components) => new Map(components.map((c) => [`${c.name}@${c.version}`, c]));
const deps = (c) => c.dependsOn.map((d) => `${d.name}@${d.version}`);

describe('package-lock.json v3', () => {
  const { components, warnings } = parseNpmLockfile(json('package-lock-v3.json'), { source: 'package-lock.json' });
  const c = byKey(components);

  test('lists every registry package, sorted', () => {
    expect([...c.keys()]).toEqual([
      '@babel/core@7.0.0', 'body-parser@1.19.0', 'debug@2.6.9', 'debug@4.3.4', 'express@4.17.1',
      'jest-lite@1.2.0', 'left-pad@1.3.0', 'lodash@4.17.21', 'ms@2.0.0', 'ms@2.1.2', 'qs@6.7.0',
    ]);
  });

  test('direct deps come from the root and from workspaces', () => {
    const direct = components.filter((x) => x.direct).map((x) => x.name);
    expect(direct).toEqual(['@babel/core', 'express', 'jest-lite', 'left-pad', 'lodash']);
  });

  test('dev flag and license are copied from the entry', () => {
    expect(c.get('jest-lite@1.2.0')).toMatchObject({ dev: true, license: 'MIT' });
    expect(c.get('qs@6.7.0')).toMatchObject({ dev: false, license: 'BSD-3-Clause' });
  });

  test('dependencies resolve to the nearest node_modules copy', () => {
    expect(deps(c.get('express@4.17.1'))).toEqual(['body-parser@1.19.0', 'debug@2.6.9']);
    expect(deps(c.get('@babel/core@7.0.0'))).toEqual(['debug@4.3.4']);      // nested copy
    expect(deps(c.get('debug@4.3.4'))).toEqual(['ms@2.1.2']);               // nested copy
    expect(deps(c.get('debug@2.6.9'))).toEqual(['ms@2.0.0']);               // hoisted copy
  });

  test('a missing peer dependency is ignored', () => {
    expect(c.get('jest-lite@1.2.0').dependsOn).toEqual([]);
  });

  test('an npm alias is reported under its real name', () => {
    expect(c.get('lodash@4.17.21')).toMatchObject({ direct: true });
  });

  test('links, workspace folders and extraneous entries are not components', () => {
    expect(components.find((x) => x.name === 'ui' || x.name === 'old-thing')).toBeUndefined();
  });

  test('every component is exact and records its source', () => {
    expect(components.every((x) => x.approximate === false && x.source === 'package-lock.json' && x.ecosystem === 'npm')).toBe(true);
  });

  test('git dependencies are skipped with a warning', () => {
    expect(warnings).toEqual([
      'package-lock.json: skipped 1 dependency not from the registry (git, file, link or URL): gitdep',
    ]);
  });
});

describe('package-lock.json v2', () => {
  test('gives the same result as v3 (the legacy "dependencies" section is ignored)', () => {
    const v3 = json('package-lock-v3.json');
    const v2 = { ...v3, lockfileVersion: 2, dependencies: { express: { version: '4.17.1' } } };
    expect(parseNpmLockfile(v2, { source: 'x' })).toEqual(parseNpmLockfile(v3, { source: 'x' }));
  });
});

describe('package-lock.json v1', () => {
  const manifest = {
    dependencies: { express: '^4.16.0', gitpkg: 'git+https://github.com/u/gitpkg.git', aliased: 'npm:left-pad@^1.3.0' },
    devDependencies: { mocha: '^5.0.0' },
  };

  test('walks the nested tree and resolves "requires"', () => {
    const { components, warnings } = parseNpmLockfile(json('package-lock-v1.json'), { source: 'package-lock.json', companion: manifest });
    const c = byKey(components);
    expect([...c.keys()]).toEqual([
      'debug@2.6.9', 'debug@3.1.0', 'express@4.16.0', 'left-pad@1.3.0', 'mocha@5.0.0', 'ms@2.0.0', 'qs@6.5.1',
    ]);
    expect(deps(c.get('express@4.16.0'))).toEqual(['debug@2.6.9', 'qs@6.5.1']);
    expect(deps(c.get('mocha@5.0.0'))).toEqual(['debug@3.1.0']);   // its own nested copy
    expect(deps(c.get('debug@3.1.0'))).toEqual(['ms@2.0.0']);       // found at the top level
    expect(c.get('debug@3.1.0')).toMatchObject({ dev: true, direct: false, license: null });
    expect(components.filter((x) => x.direct).map((x) => x.name)).toEqual(['express', 'left-pad', 'mocha']);
    expect(warnings).toEqual([
      'package-lock.json: skipped 1 dependency not from the registry (git, file, link or URL): gitpkg',
    ]);
  });

  test('without package.json, direct = top-level packages nothing else requires', () => {
    const { components } = parseNpmLockfile(json('package-lock-v1.json'), { source: 'package-lock.json' });
    expect(components.filter((x) => x.direct).map((x) => x.name)).toEqual(['express', 'left-pad', 'mocha']);
  });
});

describe('invalid input', () => {
  test.each([
    ['not an object', []],
    ['no packages or dependencies', { lockfileVersion: 3 }],
  ])('%s raises ParseError', (_label, lock) => {
    expect(() => parseNpmLockfile(lock, { source: 'package-lock.json' })).toThrow(ParseError);
  });

  test('odd entry values are skipped, not crashed on', () => {
    const lock = { packages: { '': {}, 'node_modules/a': 'oops', 'node_modules/b': { version: 42 }, 'node_modules/__proto__': { version: '1.0.0' } } };
    const { components } = parseNpmLockfile(lock, { source: 'x' });
    expect(components.map((x) => x.name)).toEqual(['__proto__']);
  });
});
