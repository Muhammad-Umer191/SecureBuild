const fs = require('node:fs/promises');
const path = require('node:path');
const { walkTree } = require('../../../src/services/discovery/walkTree');
const { makeRepo, removeRepo } = require('../helpers');

let root;
afterEach(() => removeRepo(root));

const OPTS = {
  fileNames: new Set(['package-lock.json', 'package.json']),
  ignoreDirs: ['node_modules', '.git'],
  skipDirs: ['tests'],
  maxDepth: 20,
  maxEntries: 1000,
};

describe('walkTree', () => {
  test('reports matching files with relative "/" paths and their folder', async () => {
    root = await makeRepo({ 'package.json': '{}', 'a/b/package-lock.json': '{}', 'README.md': '' });
    const { files } = await walkTree(root, OPTS);
    expect(files).toEqual([
      { path: 'package.json', dir: '', name: 'package.json', skipped: false },
      { path: 'a/b/package-lock.json', dir: 'a/b', name: 'package-lock.json', skipped: false },
    ]);
  });

  test('never enters ignored folders', async () => {
    root = await makeRepo({ 'node_modules/x/package.json': '{}', '.git/package.json': '{}' });
    const { files, stats } = await walkTree(root, OPTS);
    expect(files).toEqual([]);
    expect(stats.ignoredDirs).toBe(2);
  });

  test('marks files inside skip folders (at any depth) as skipped', async () => {
    root = await makeRepo({ 'tests/fixtures/app/package.json': '{}', 'src/package.json': '{}' });
    const { files } = await walkTree(root, OPTS);
    expect(files.map((f) => [f.path, f.skipped])).toEqual([
      ['src/package.json', false],
      ['tests/fixtures/app/package.json', true],
    ]);
  });

  test('ignores symlinked files and does not enter symlinked folders', async () => {
    root = await makeRepo({ 'real/package.json': '{}' });
    await fs.symlink(path.join(root, 'real/package.json'), path.join(root, 'package-lock.json'));
    await fs.symlink(path.join(root, 'real'), path.join(root, 'linked-dir'));
    const { files } = await walkTree(root, OPTS);
    expect(files.map((f) => f.path)).toEqual(['real/package.json']);
  });

  test('stops descending past maxDepth', async () => {
    root = await makeRepo({ 'a/package.json': '{}', 'a/b/c/package.json': '{}' });
    const { files, truncated } = await walkTree(root, { ...OPTS, maxDepth: 2 });
    expect(files.map((f) => f.path)).toEqual(['a/package.json']);
    expect(truncated).toBe('depth');
  });

  test('stops after maxEntries', async () => {
    const many = Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`d${i}/package.json`, '{}']));
    root = await makeRepo(many);
    const { truncated, files } = await walkTree(root, { ...OPTS, maxEntries: 5 });
    expect(truncated).toBe('entries');
    expect(files.length).toBeLessThan(10);
  });
});
