// Downloads a public GitHub repo into a temp folder so its lockfiles can be read.
//
// Built from:
//   repoUrl.js      only https://github.com/<owner>/<repo> is accepted
//   gitRunner.js    git runs locked down (no shell, no secrets, no credentials)
//   dirSize.js      size limit checked while the clone runs
//   cloneErrors.js  failures become CloneError with a code
//
// Shallow clone (latest commit of the default branch), no tags, submodules or
// LFS files. The temp folder is always removed: here on failure, otherwise by
// the caller (withClone() does that for you).
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const config = require('../../config');
const { parseRepoUrl, isValidRepoUrl } = require('./repoUrl');
const { runGit } = require('./gitRunner');
const { dirSize, watchDirSize } = require('./dirSize');
const { CloneError, mapGitError } = require('./cloneErrors');

const TMP_PREFIX = 'securebuild-clone-';

const tooLargeError = (maxSizeMb) =>
  new CloneError('REPO_TOO_LARGE', `Repository is larger than ${maxSizeMb} MB`, { permanent: true });

/**
 * Removes a clone folder created by cloneRepo. Safe to call twice. Refuses any
 * path that is not one of our temp folders, so a bad argument can't delete
 * something else.
 */
async function removeClone(dir) {
  if (typeof dir !== 'string' || !path.isAbsolute(dir) || !path.basename(dir).startsWith(TMP_PREFIX)) {
    throw new Error(`Refusing to remove non-clone path: ${dir}`);
  }
  await fs.rm(dir, { recursive: true, force: true });
}

/**
 * Shallow-clones a public GitHub repo into a new temp folder.
 * The caller must call removeClone(dir) when done (or use withClone).
 *
 * @param {string} url  https://github.com/<owner>/<repo>
 * @param {Object} [opts]
 * @param {number} [opts.timeoutMs]  default config.scanner.cloneTimeoutMs
 * @param {number} [opts.maxSizeMb]  default config.scanner.repoMaxSizeMb
 * @param {number} [opts.depth]      default config.scanner.cloneMaxDepth
 * @param {string} [opts.baseDir]    where temp folders are created (default: OS temp dir)
 * @returns {Promise<{dir: string, commitSha: string}>}
 */
async function cloneRepo(url, opts = {}) {
  const parsed = parseRepoUrl(url);
  if (!parsed) {
    throw new CloneError('INVALID_URL', 'Only https://github.com/<owner>/<repo> URLs are allowed', { permanent: true });
  }

  const {
    timeoutMs = config.scanner.cloneTimeoutMs,
    maxSizeMb = config.scanner.repoMaxSizeMb,
    depth = config.scanner.cloneMaxDepth,
    baseDir = os.tmpdir(),
  } = opts;
  const maxBytes = maxSizeMb * 1024 * 1024;

  const dir = await fs.mkdtemp(path.join(baseDir, TMP_PREFIX));
  try {
    await runClone(parsed.cloneUrl, dir, { timeoutMs, maxBytes, maxSizeMb, depth });

    // The clone can finish between two size checks, so check once more.
    if ((await dirSize(dir, maxBytes)) > maxBytes) throw tooLargeError(maxSizeMb);

    const commitSha = await runGit(['rev-parse', 'HEAD'], { cwd: dir, timeoutMs: 10_000 });
    if (!/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(commitSha)) {
      throw new CloneError('CLONE_FAILED', 'Could not read the commit SHA');
    }
    return { dir, commitSha };
  } catch (err) {
    await removeClone(dir);
    throw err;
  }
}

// Runs `git clone`, killing it if the folder grows past the size limit, and
// turns any failure into a CloneError.
async function runClone(cloneUrl, dir, { timeoutMs, maxBytes, maxSizeMb, depth }) {
  let child;
  let tooLarge = false;
  const stopWatching = watchDirSize(dir, maxBytes, () => {
    tooLarge = true;
    if (child) child.kill('SIGKILL');
  });

  const args = [
    'clone',
    '--depth', String(depth),
    '--single-branch',
    '--no-tags',
    '--no-recurse-submodules',
    '--quiet',
    '--',            // everything after this is a URL/path, never an option
    cloneUrl,
    dir,
  ];

  try {
    await runGit(args, { timeoutMs, onSpawn: (c) => { child = c; } });
  } catch (err) {
    if (tooLarge) throw tooLargeError(maxSizeMb);
    if (err.code === 'ENOENT') throw new CloneError('GIT_NOT_INSTALLED', 'git is not installed on the server');
    if (err.killed) throw new CloneError('CLONE_TIMEOUT', `Clone took longer than ${timeoutMs / 1000}s`);
    throw mapGitError(err.stderr);
  } finally {
    stopWatching();
  }
}

/**
 * Clones, runs `fn({dir, commitSha})`, and always removes the clone afterwards,
 * even if `fn` throws. Returns what `fn` returns.
 */
async function withClone(url, fn, opts) {
  const clone = await cloneRepo(url, opts);
  try {
    return await fn(clone);
  } finally {
    await removeClone(clone.dir);
  }
}

module.exports = { cloneRepo, removeClone, withClone, isValidRepoUrl, CloneError };
