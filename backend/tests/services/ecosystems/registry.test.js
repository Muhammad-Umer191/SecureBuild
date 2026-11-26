const { registry, createRegistry, DEFAULT_ECOSYSTEMS } = require('../../../src/services/ecosystems');
const { discoverDependencyFiles } = require('../../../src/services/discovery');
const { parseSources } = require('../../../src/services/parsers');
const { selectSources } = require('../../../src/services/discovery/selectSources');
const { makeRepo, removeRepo } = require('../helpers');

describe('default registry', () => {
  test('has npm and PyPI, and every file name maps to one ecosystem', () => {
    expect(registry.ecosystems.map((e) => e.ecosystem)).toEqual(['npm', 'PyPI']);
    expect(registry.lookup('package-lock.json')).toMatchObject({ kind: 'lockfile', eco: { ecosystem: 'npm' } });
    expect(registry.lookup('requirements.txt')).toMatchObject({ kind: 'manifest', eco: { ecosystem: 'PyPI' } });
    expect(registry.lookup('yarn.lock')).toMatchObject({ kind: 'unsupported', eco: { ecosystem: 'npm' } });
    expect(registry.lookup('README.md')).toBeUndefined();
  });

  test('lists supported files lockfiles first', () => {
    expect(registry.supportedFiles).toEqual([
      'package-lock.json', 'poetry.lock', 'package.json', 'pyproject.toml', 'requirements.txt',
    ]);
  });
});

describe('createRegistry validation', () => {
  const valid = {
    ecosystem: 'Go',
    lockfiles: [],
    manifests: [{ filename: 'go.mod', format: 'text', parse: () => ({}) }],
    unsupportedLockfiles: [],
    lockfileScope: 'folder',
    normalizeName: (n) => n,
    purl: (n, v) => `pkg:golang/${n}@${v}`,
  };

  test('accepts a complete descriptor', () => {
    expect(() => createRegistry([...DEFAULT_ECOSYSTEMS, valid])).not.toThrow();
  });

  test.each([
    ['a missing name', { ...valid, ecosystem: '' }, /needs a name/],
    ['a missing list', { ...valid, manifests: undefined }, /manifests must be an array/],
    ['a handler without parse()', { ...valid, manifests: [{ filename: 'go.mod', format: 'text' }] }, /needs filename, format/],
    ['an unknown format', { ...valid, manifests: [{ filename: 'go.mod', format: 'yaml', parse: () => ({}) }] }, /needs filename, format/],
    ['a bad scope', { ...valid, lockfileScope: 'everywhere' }, /lockfileScope/],
    ['a companion that is not a manifest', {
      ...valid, lockfiles: [{ filename: 'go.sum', format: 'text', companion: 'nope.mod', parse: () => ({}) }],
    }, /companion nope.mod must also be listed/],
    ['a missing purl()', { ...valid, purl: undefined }, /purl must be a function/],
    ['a missing normalizeName()', { ...valid, normalizeName: 'lowercase' }, /normalizeName must be a function/],
  ])('rejects %s', (_label, descriptor, message) => {
    expect(() => createRegistry([descriptor])).toThrow(message);
  });

  test('rejects the same ecosystem registered twice', () => {
    expect(() => createRegistry([valid, valid])).toThrow('ecosystem "Go" is registered twice');
  });

  test('looks descriptors up by ecosystem name', () => {
    const reg = createRegistry([...DEFAULT_ECOSYSTEMS, valid]);
    expect(reg.get('Go')).toBe(valid);
    expect(reg.get('PyPI').ecosystem).toBe('PyPI');
    expect(reg.get('Cargo')).toBeUndefined();
  });

  test('rejects two ecosystems claiming the same file', () => {
    const clash = { ...valid, manifests: [{ filename: 'package.json', format: 'json', parse: () => ({}) }] };
    expect(() => createRegistry([...DEFAULT_ECOSYSTEMS, clash])).toThrow('package.json is claimed by both npm and Go');
  });
});

describe('adding an ecosystem needs no changes to discovery or parsers', () => {
  // A toy Go ecosystem: go.sum lines are "module version hash".
  const go = {
    ecosystem: 'Go',
    lockfiles: [{
      filename: 'go.sum',
      format: 'text',
      companion: 'go.mod',
      parse: (text, { source, companion }) => ({
        components: text.trim().split('\n').map((line) => {
          const [name, version] = line.split(' ');
          return {
            name, version, ecosystem: 'Go', direct: companion.includes(name), dev: false,
            license: null, dependsOn: [], source, approximate: false,
          };
        }),
        warnings: [],
      }),
    }],
    manifests: [{ filename: 'go.mod', format: 'text', parse: () => ({ components: [], warnings: [] }) }],
    unsupportedLockfiles: [],
    lockfileScope: 'folder',
    normalizeName: (n) => n,
    purl: (n, v) => `pkg:golang/${n}@${v}`,
  };
  const withGo = createRegistry([...DEFAULT_ECOSYSTEMS, go]);

  let root;
  afterEach(() => removeRepo(root));

  test('discovery and parsing (including purls) both handle go.sum next to npm', async () => {
    root = await makeRepo({
      'svc/go.mod': 'module svc\nrequire github.com/pkg/errors v0.9.1\n',
      'svc/go.sum': 'github.com/pkg/errors v0.9.1 h1:abc\ngolang.org/x/text v0.3.0 h1:def\n',
      'web/package.json': '{"dependencies": {"express": "^4.0.0"}}',
    });

    const { sources } = await discoverDependencyFiles(root, { registry: withGo });
    expect(sources.map((s) => [s.path, s.ecosystem, s.kind, s.manifestPath])).toEqual([
      ['svc/go.sum', 'Go', 'lockfile', 'svc/go.mod'],
      ['web/package.json', 'npm', 'manifest', null],
    ]);

    const { components } = await parseSources(root, sources, { registry: withGo });
    expect(components.map((c) => `${c.ecosystem}:${c.name}@${c.version}${c.direct ? ' direct' : ''}`)).toEqual([
      'Go:github.com/pkg/errors@v0.9.1 direct',
      'Go:golang.org/x/text@v0.3.0',
      'npm:express@4.0.0 direct',
    ]);
    expect(components.map((c) => c.purl)).toEqual([
      'pkg:golang/github.com/pkg/errors@v0.9.1',
      'pkg:golang/golang.org/x/text@v0.3.0',
      'pkg:npm/express@4.0.0',
    ]);
  });

  test('without it registered, the same repo ignores the Go files', async () => {
    root = await makeRepo({ 'svc/go.sum': 'x v1 h1:a\n' });
    const { sources } = await discoverDependencyFiles(root);
    expect(sources).toEqual([]);
  });
});

describe('shared rule for unsupported lockfiles', () => {
  test('Pipfile.lock next to requirements.txt now says which file is used instead', () => {
    const files = [
      { path: 'svc/Pipfile.lock', dir: 'svc', name: 'Pipfile.lock', skipped: false },
      { path: 'svc/requirements.txt', dir: 'svc', name: 'requirements.txt', skipped: false },
    ];
    const { sources, warnings } = selectSources(files);
    expect(sources.map((s) => s.path)).toEqual(['svc/requirements.txt']);
    expect(warnings).toEqual(['svc/Pipfile.lock is not supported yet; using svc/requirements.txt instead (approximate)']);
  });
});
