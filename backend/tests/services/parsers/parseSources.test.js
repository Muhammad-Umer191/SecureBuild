const fs = require('node:fs/promises');
const path = require('node:path');
const { parseSources } = require('../../../src/services/parsers');
const { makeRepo, removeRepo } = require('../helpers');
const { text } = require('../fixtures');

let root;
afterEach(() => removeRepo(root));

const src = (p, kind, manifestPath = null) => ({
  path: p, filename: p.split('/').pop(), kind, manifestPath,
});

describe('parseSources', () => {
  test('parses a mixed monorepo and labels each component with its source', async () => {
    root = await makeRepo({
      'package-lock.json': text('package-lock-v3.json'),
      'package.json': '{}',
      'api/poetry.lock': text('poetry-groups.lock'),
      'api/pyproject.toml': text('pyproject-poetry.toml'),
      'tools/requirements.txt': 'black==23.1.0\n',
    });
    const { components, warnings } = await parseSources(root, [
      src('package-lock.json', 'lockfile', 'package.json'),
      src('api/poetry.lock', 'lockfile', 'api/pyproject.toml'),
      src('tools/requirements.txt', 'manifest'),
    ]);

    const count = (s) => components.filter((c) => c.source === s).length;
    expect(count('package-lock.json')).toBe(11);
    expect(count('api/poetry.lock')).toBe(7);
    expect(components.find((c) => c.source === 'tools/requirements.txt')).toMatchObject({
      name: 'black', version: '23.1.0', approximate: true,
    });
    expect(warnings).toHaveLength(2);   // gitdep (npm) and mylib (poetry)
  });

  test('one broken file becomes a warning; the others still parse', async () => {
    root = await makeRepo({
      'a/package-lock.json': '{ not json',
      'b/package.json': '{"dependencies": {"express": "^4.0.0"}}',
      'c/poetry.lock': '[[package]\nbroken',
    });
    const { components, warnings } = await parseSources(root, [
      src('a/package-lock.json', 'lockfile'),
      src('b/package.json', 'manifest'),
      src('c/poetry.lock', 'lockfile'),
    ]);
    expect(components.map((c) => c.name)).toEqual(['express']);
    expect(warnings).toEqual([
      'a/package-lock.json: could not be read (invalid JSON)',
      'c/poetry.lock: could not be read (invalid TOML)',
    ]);
  });

  test('a broken companion manifest is a warning, and the lockfile still parses', async () => {
    root = await makeRepo({
      'poetry.lock': text('poetry-groups.lock'),
      'pyproject.toml': 'this is = = not toml',
    });
    const { components, warnings } = await parseSources(root, [src('poetry.lock', 'lockfile', 'pyproject.toml')]);
    expect(components).toHaveLength(7);
    expect(warnings[0]).toBe('pyproject.toml: could not be read (invalid TOML); direct/dev flags for its lockfile are estimated');
  });

  test('paths outside the repo and symlinks are refused', async () => {
    root = await makeRepo({ 'real.txt': 'x==1.0\n' });
    await fs.symlink(path.join(root, 'real.txt'), path.join(root, 'requirements.txt'));
    const { components, warnings } = await parseSources(root, [
      src('../outside/package.json', 'manifest'),
      src('requirements.txt', 'manifest'),
    ]);
    expect(components).toEqual([]);
    expect(warnings).toEqual([
      '../outside/package.json: path is outside the repository',
      'requirements.txt: not a regular file',
    ]);
  });
});
