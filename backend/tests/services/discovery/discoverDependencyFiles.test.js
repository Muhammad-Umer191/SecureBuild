const { discoverDependencyFiles } = require('../../../src/services/discovery');
const { makeRepo, removeRepo } = require('./helpers');

let root;
afterEach(() => removeRepo(root));

describe('discoverDependencyFiles', () => {
  test('a monorepo with mixed projects', async () => {
    root = await makeRepo({
      'package.json': '{}',
      'package-lock.json': '{}',
      'packages/ui/package.json': '{}',      // workspace, covered by the root lockfile
      'services/api/pyproject.toml': '',
      'services/api/poetry.lock': '',
      'tools/requirements.txt': '',          // no lock: fallback
      'node_modules/lodash/package.json': '{}',
      'README.md': '',
    });
    const { sources, warnings, stats } = await discoverDependencyFiles(root);

    expect(sources).toEqual([
      { path: 'package-lock.json', filename: 'package-lock.json', ecosystem: 'npm', kind: 'lockfile', manifestPath: 'package.json' },
      { path: 'services/api/poetry.lock', filename: 'poetry.lock', ecosystem: 'PyPI', kind: 'lockfile', manifestPath: 'services/api/pyproject.toml' },
      { path: 'tools/requirements.txt', filename: 'requirements.txt', ecosystem: 'PyPI', kind: 'manifest', manifestPath: null },
    ]);
    expect(warnings).toEqual([
      'tools/requirements.txt: no lockfile, so only direct dependencies are scanned and their versions are estimated',
    ]);
    expect(stats.ignoredDirs).toBe(1);
  });

  test('test/example folders are skipped with one count warning', async () => {
    root = await makeRepo({
      'poetry.lock': '',
      'pyproject.toml': '',
      'tests/fixtures/a/poetry.lock': '',
      'tests/fixtures/b/poetry.lock': '',
      'examples/demo/package.json': '{}',
      'playground/app/package.json': '{}',
    });
    const { sources, warnings } = await discoverDependencyFiles(root);
    expect(sources.map((s) => s.path)).toEqual(['poetry.lock']);
    expect(warnings).toEqual(['4 dependency files inside test/example folders were skipped']);
  });

  test('skipDirs: [] scans test folders too', async () => {
    root = await makeRepo({ 'tests/fixtures/a/poetry.lock': '' });
    const { sources, warnings } = await discoverDependencyFiles(root, { skipDirs: [] });
    expect(sources.map((s) => s.path)).toEqual(['tests/fixtures/a/poetry.lock']);
    expect(warnings).toEqual([]);
  });

  test('an oversized lockfile is skipped and its manifest becomes the fallback', async () => {
    root = await makeRepo({ 'package.json': '{}', 'package-lock.json': 'x'.repeat(2048) });
    const { sources, warnings } = await discoverDependencyFiles(root, { maxFileSizeMb: 0.001 });
    expect(sources.map((s) => [s.path, s.kind])).toEqual([['package.json', 'manifest']]);
    expect(warnings[0]).toBe('package-lock.json is larger than 0.001 MB and was skipped');
  });

  test('hitting the depth cap adds a warning', async () => {
    root = await makeRepo({ 'package-lock.json': '{}', 'a/b/c/d/package.json': '{}' });
    const { warnings } = await discoverDependencyFiles(root, { maxDepth: 2 });
    expect(warnings).toContain('Folders deeper than 2 levels were not searched; results may be incomplete');
  });

  test('hitting the entry cap adds a warning', async () => {
    root = await makeRepo(Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`f${i}.txt`, ''])));
    const { warnings } = await discoverDependencyFiles(root, { maxEntries: 5 });
    expect(warnings).toContain('Search stopped after 5 entries; results may be incomplete');
  });

  test('a repo with no dependency files says so', async () => {
    root = await makeRepo({ 'README.md': '', 'main.go': '' });
    const { sources, warnings } = await discoverDependencyFiles(root);
    expect(sources).toEqual([]);
    expect(warnings).toEqual([
      'No dependency files found (package-lock.json, poetry.lock, package.json, pyproject.toml, requirements.txt)',
    ]);
  });
});
