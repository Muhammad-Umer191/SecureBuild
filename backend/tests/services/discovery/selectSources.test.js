const { selectSources } = require('../../../src/services/discovery/selectSources');

// ['a/package.json', 'package-lock.json'] -> walkTree-style entries, sorted
const files = (paths) =>
  [...paths].sort().map((p) => {
    const i = p.lastIndexOf('/');
    return { path: p, dir: i === -1 ? '' : p.slice(0, i), name: p.slice(i + 1), skipped: false };
  });

describe('selectSources', () => {
  test('npm lockfile wins over package.json, and points to it as its manifest', () => {
    const { sources, warnings } = selectSources(files(['package.json', 'package-lock.json']));
    expect(sources).toEqual([
      { path: 'package-lock.json', filename: 'package-lock.json', ecosystem: 'npm', kind: 'lockfile', manifestPath: 'package.json' },
    ]);
    expect(warnings).toEqual([]);
  });

  test('package.json without a lockfile is an approximate fallback', () => {
    const { sources, warnings } = selectSources(files(['package.json']));
    expect(sources).toEqual([
      { path: 'package.json', filename: 'package.json', ecosystem: 'npm', kind: 'manifest', manifestPath: null },
    ]);
    expect(warnings).toEqual(['package.json: no lockfile, so only direct dependencies are scanned and their versions are estimated']);
  });

  test('workspace packages are covered by the root lockfile', () => {
    const { sources, warnings } = selectSources(files([
      'package.json', 'package-lock.json', 'packages/a/package.json', 'packages/b/nested/package.json',
    ]));
    expect(sources.map((s) => s.path)).toEqual(['package-lock.json']);
    expect(warnings).toEqual([]);
  });

  test('a lockfile in a sibling folder does not cover another project', () => {
    const { sources } = selectSources(files(['web/package-lock.json', 'web/package.json', 'api/package.json']));
    expect(sources.map((s) => [s.path, s.kind])).toEqual([
      ['api/package.json', 'manifest'],
      ['web/package-lock.json', 'lockfile'],
    ]);
  });

  test('poetry.lock covers pyproject.toml and requirements.txt in the same folder only', () => {
    const { sources } = selectSources(files([
      'pyproject.toml', 'poetry.lock', 'requirements.txt', 'tools/requirements.txt',
    ]));
    expect(sources).toEqual([
      { path: 'poetry.lock', filename: 'poetry.lock', ecosystem: 'PyPI', kind: 'lockfile', manifestPath: 'pyproject.toml' },
      { path: 'tools/requirements.txt', filename: 'requirements.txt', ecosystem: 'PyPI', kind: 'manifest', manifestPath: null },
    ]);
  });

  test('pyproject.toml and requirements.txt without a lock are both returned', () => {
    const { sources } = selectSources(files(['pyproject.toml', 'requirements.txt']));
    expect(sources.map((s) => [s.path, s.ecosystem, s.kind])).toEqual([
      ['pyproject.toml', 'PyPI', 'manifest'],
      ['requirements.txt', 'PyPI', 'manifest'],
    ]);
  });

  test('a lockfile with no manifest next to it has manifestPath null', () => {
    expect(selectSources(files(['poetry.lock'])).sources[0].manifestPath).toBeNull();
  });

  test('yarn.lock warns and package.json is used instead', () => {
    const { sources, warnings } = selectSources(files(['package.json', 'yarn.lock']));
    expect(sources.map((s) => [s.path, s.kind])).toEqual([['package.json', 'manifest']]);
    expect(warnings).toEqual(['yarn.lock is not supported yet; using package.json instead (approximate)']);
  });

  test('a pnpm workspace uses only the root package.json and counts the skipped packages', () => {
    const { sources, warnings } = selectSources(files([
      'package.json', 'pnpm-lock.yaml', 'packages/a/package.json', 'packages/b/package.json', 'docs/package.json',
    ]));
    expect(sources.map((s) => [s.path, s.kind])).toEqual([['package.json', 'manifest']]);
    expect(warnings).toEqual([
      'pnpm-lock.yaml is not supported yet; using package.json instead (approximate). 3 workspace packages under it were not scanned',
    ]);
  });

  test('a yarn.lock in one project does not hide a sibling project', () => {
    const { sources } = selectSources(files([
      'web/package.json', 'web/yarn.lock', 'web/packages/x/package.json', 'api/package.json',
    ]));
    expect(sources.map((s) => s.path)).toEqual(['api/package.json', 'web/package.json']);
  });

  test('Pipfile.lock warns that nothing there was scanned', () => {
    const { sources, warnings } = selectSources(files(['svc/Pipfile.lock']));
    expect(sources).toEqual([]);
    expect(warnings).toEqual(['svc/Pipfile.lock is not supported yet; dependencies in svc/ were not scanned']);
  });

  test('more than 5 approximate warnings are folded into one line', () => {
    const paths = Array.from({ length: 7 }, (_, i) => `pkg${i}/package.json`);
    const { sources, warnings } = selectSources(files(paths));
    expect(sources).toHaveLength(7);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/^7 folders have no lockfile/);
    expect(warnings[0]).toMatch(/and 2 more$/);
  });

  test('exactly 5 warnings are kept as separate lines', () => {
    const paths = Array.from({ length: 5 }, (_, i) => `pkg${i}/package.json`);
    expect(selectSources(files(paths)).warnings).toHaveLength(5);
  });
});
