// Offline tests always run. Tests that clone from GitHub run only with
// NETWORK_TESTS=1, e.g. `NETWORK_TESTS=1 npx jest tests/services/clone`.
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { cloneRepo, removeClone, withClone } = require('../../../src/services/clone/repoCloneService');

describe('removeClone', () => {
  let tmp;
  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'securebuild-clone-'));
  });
  afterEach(() => fs.rm(tmp, { recursive: true, force: true }));

  test('deletes our temp folder and tolerates a second call', async () => {
    await removeClone(tmp);
    await expect(fs.access(tmp)).rejects.toThrow();
    await expect(removeClone(tmp)).resolves.toBeUndefined();
  });

  test.each([
    ['a non-clone folder', () => os.tmpdir()],
    ['a relative path', () => 'securebuild-clone-x'],
    ['the root', () => '/'],
  ])('refuses %s', async (_label, dir) => {
    await expect(removeClone(dir())).rejects.toThrow('Refusing to remove');
  });
});

describe('cloneRepo input checks', () => {
  test('rejects an invalid URL before running git', async () => {
    await expect(cloneRepo('https://evil.com/a/b')).rejects.toMatchObject({ code: 'INVALID_URL', permanent: true });
  });
});

const network = process.env.NETWORK_TESTS === '1' ? describe : describe.skip;

network('cloneRepo against GitHub', () => {
  jest.setTimeout(60_000);
  const URL = 'https://github.com/octocat/Hello-World';
  let baseDir;

  beforeEach(async () => {
    baseDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sb-test-'));
  });
  afterEach(() => fs.rm(baseDir, { recursive: true, force: true }));

  const leftovers = async () => (await fs.readdir(baseDir)).length;

  test('clones a public repo and returns the commit SHA', async () => {
    const { dir, commitSha } = await cloneRepo(URL, { baseDir });
    expect(commitSha).toMatch(/^[0-9a-f]{40}$/);
    expect(await fs.readFile(path.join(dir, 'README'), 'utf8')).toMatch(/Hello World/);
    await removeClone(dir);
    expect(await leftovers()).toBe(0);
  });

  test('withClone removes the clone even when the callback throws', async () => {
    await expect(withClone(URL, async () => { throw new Error('boom'); }, { baseDir })).rejects.toThrow('boom');
    expect(await leftovers()).toBe(0);
  });

  test('a missing repo fails with REPO_NOT_FOUND and leaves nothing behind', async () => {
    await expect(cloneRepo('https://github.com/octocat/this-repo-does-not-exist-123', { baseDir }))
      .rejects.toMatchObject({ code: 'REPO_NOT_FOUND', permanent: true });
    expect(await leftovers()).toBe(0);
  });

  test('a repo over the size limit fails with REPO_TOO_LARGE', async () => {
    await expect(cloneRepo(URL, { baseDir, maxSizeMb: 0.001 }))
      .rejects.toMatchObject({ code: 'REPO_TOO_LARGE', permanent: true });
    expect(await leftovers()).toBe(0);
  });

  test('a clone over the time limit fails with CLONE_TIMEOUT', async () => {
    await expect(cloneRepo(URL, { baseDir, timeoutMs: 1 }))
      .rejects.toMatchObject({ code: 'CLONE_TIMEOUT' });
    expect(await leftovers()).toBe(0);
  });
});
