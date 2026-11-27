// Folder size helpers, used to enforce the repo size limit.
const fs = require('node:fs/promises');
const path = require('node:path');

const CHECK_INTERVAL_MS = 1000;

/**
 * Total size in bytes of a folder, without following symlinks. Stops counting
 * once `limit` is passed. Files that vanish mid-walk (git renames temp files)
 * are skipped.
 */
async function dirSize(dir, limit = Infinity) {
  let total = 0;
  const stack = [dir];
  while (stack.length && total <= limit) {
    const current = stack.pop();
    let entries;
    try {
      entries = await fs.readdir(current, { withFileTypes: true });
    } catch (err) {
      if (err.code === 'ENOENT') continue;
      throw err;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        try {
          total += (await fs.lstat(full)).size;
        } catch (err) {
          if (err.code !== 'ENOENT') throw err;
        }
      }
    }
  }
  return total;
}

/**
 * Checks `dir` every second and calls `onExceed()` once if it grows past
 * `maxBytes`. Returns a function that stops watching.
 */
function watchDirSize(dir, maxBytes, onExceed, intervalMs = CHECK_INTERVAL_MS) {
  let checking = false;
  let fired = false;

  const timer = setInterval(async () => {
    if (checking || fired) return;
    checking = true;
    try {
      if ((await dirSize(dir, maxBytes)) > maxBytes) {
        fired = true;
        onExceed();
      }
    } catch {
      // A failed check is not fatal; the caller still checks once at the end.
    } finally {
      checking = false;
    }
  }, intervalMs);

  return () => clearInterval(timer);
}

module.exports = { dirSize, watchDirSize };
