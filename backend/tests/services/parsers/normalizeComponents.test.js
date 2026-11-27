const { normalizeComponents } = require('../../../src/services/parsers/normalizeComponents');
const { parseNpmLockfile } = require('../../../src/services/ecosystems/npm/lockfile');
const { json } = require('../fixtures');

// A raw component as the parsers produce it, with overridable fields.
const raw = (name, version, extra = {}) => ({
  name, version, ecosystem: 'npm', direct: false, dev: false, license: null,
  dependsOn: [], source: 'package-lock.json', approximate: false, ...extra,
});

describe('normalizeComponents', () => {
  test('adds purls, turns dependsOn into purls and sorts by purl', () => {
    const { components } = normalizeComponents([
      raw('express', '4.17.1', { direct: true, dependsOn: [{ name: '@babel/core', version: '7.0.0' }] }),
      raw('@babel/core', '7.0.0'),
    ]);
    expect(components).toEqual([
      {
        name: '@babel/core', version: '7.0.0', ecosystem: 'npm', purl: 'pkg:npm/%40babel/core@7.0.0',
        direct: false, dev: false, license: null, dependsOn: [], source: 'package-lock.json', approximate: false,
      },
      {
        name: 'express', version: '4.17.1', ecosystem: 'npm', purl: 'pkg:npm/express@4.17.1',
        direct: true, dev: false, license: null, dependsOn: ['pkg:npm/%40babel/core@7.0.0'],
        source: 'package-lock.json', approximate: false,
      },
    ]);
  });

  test('merges duplicates: direct if any, dev/approximate only if all', () => {
    const { components, stats } = normalizeComponents([
      raw('lodash', '4.17.21', { source: 'web/package-lock.json', dev: true, direct: false }),
      raw('lodash', '4.17.21', { source: 'api/package-lock.json', dev: false, direct: true, license: 'MIT' }),
      raw('lodash', '4.17.21', { source: 'tools/package.json', dev: true, approximate: true }),
    ]);
    expect(components).toHaveLength(1);
    expect(components[0]).toMatchObject({
      direct: true,          // listed directly in api/
      dev: false,            // used in production in api/
      approximate: false,    // two exact lockfile entries beat one estimate
      license: 'MIT',        // first known license
      source: 'api/package-lock.json',   // first file alphabetically
    });
    expect(stats).toEqual({ raw: 3, unique: 1, duplicatesMerged: 2, linksDropped: 0 });
  });

  test('an all-dev, all-approximate package stays dev and approximate', () => {
    const { components } = normalizeComponents([
      raw('jest', '29.0.0', { dev: true, approximate: true, source: 'a/package.json' }),
      raw('jest', '29.0.0', { dev: true, approximate: true, source: 'b/package.json' }),
    ]);
    expect(components[0]).toMatchObject({ dev: true, approximate: true });
  });

  test('different versions of one package stay separate', () => {
    const { components } = normalizeComponents([raw('debug', '2.6.9'), raw('debug', '4.3.4')]);
    expect(components.map((c) => c.purl)).toEqual(['pkg:npm/debug@2.6.9', 'pkg:npm/debug@4.3.4']);
  });

  test('dependency links of all copies are combined, de-duplicated and sorted', () => {
    const { components } = normalizeComponents([
      raw('a', '1.0.0', { dependsOn: [{ name: 'c', version: '1.0.0' }] }),
      raw('a', '1.0.0', { dependsOn: [{ name: 'b', version: '1.0.0' }, { name: 'c', version: '1.0.0' }] }),
      raw('b', '1.0.0'),
      raw('c', '1.0.0'),
    ]);
    expect(components[0].dependsOn).toEqual(['pkg:npm/b@1.0.0', 'pkg:npm/c@1.0.0']);
  });

  test('links to packages not in the list, and self-links, are dropped', () => {
    const { components, stats } = normalizeComponents([
      raw('a', '1.0.0', { dependsOn: [{ name: 'skipped-git-dep', version: '1.0.0' }, { name: 'a', version: '1.0.0' }] }),
    ]);
    expect(components[0].dependsOn).toEqual([]);
    expect(stats.linksDropped).toBe(1);
  });

  test('PyPI names are normalized, so different spellings merge', () => {
    const py = (name, source, deps = []) => ({
      ...raw(name, '0.6.2', { source, dependsOn: deps }), ecosystem: 'PyPI',
    });
    const { components } = normalizeComponents([
      py('Flask_Login', 'poetry.lock', [{ name: 'Flask', version: '2.3.0' }]),
      py('flask-login', 'requirements.txt'),
      { ...py('flask', 'poetry.lock'), version: '2.3.0' },
    ]);
    // Sorted by character code: "-" (0x2D) comes before "@" (0x40).
    expect(components.map((c) => [c.name, c.purl, c.dependsOn])).toEqual([
      ['flask-login', 'pkg:pypi/flask-login@0.6.2', ['pkg:pypi/flask@2.3.0']],
      ['flask', 'pkg:pypi/flask@2.3.0', []],
    ]);
  });

  test('the same name in two ecosystems stays separate', () => {
    const { components } = normalizeComponents([
      raw('requests', '2.31.0'),
      { ...raw('requests', '2.31.0'), ecosystem: 'PyPI' },
    ]);
    expect(components.map((c) => c.purl)).toEqual(['pkg:npm/requests@2.31.0', 'pkg:pypi/requests@2.31.0']);
  });

  test('an unknown ecosystem is a programming error', () => {
    expect(() => normalizeComponents([{ ...raw('x', '1'), ecosystem: 'Cargo' }])).toThrow('No ecosystem registered for "Cargo"');
  });

  test('works on real parser output (npm v3 fixture)', () => {
    const parsed = parseNpmLockfile(json('package-lock-v3.json'), { source: 'package-lock.json' });
    const { components, stats } = normalizeComponents(parsed.components);
    expect(stats).toEqual({ raw: 11, unique: 11, duplicatesMerged: 0, linksDropped: 0 });
    const express = components.find((c) => c.name === 'express');
    expect(express.dependsOn).toEqual(['pkg:npm/body-parser@1.19.0', 'pkg:npm/debug@2.6.9']);
    const babel = components.find((c) => c.name === '@babel/core');
    expect(babel).toMatchObject({ purl: 'pkg:npm/%40babel/core@7.0.0', dependsOn: ['pkg:npm/debug@4.3.4'] });
  });
});
