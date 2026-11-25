// Walks a folder tree and reports files whose names we care about.
//
// The tree is untrusted, so the walk:
// - never follows symlinks (readdir's Dirent describes the link itself, and
//   links are neither entered nor reported),
// - stops descending past `maxDepth` and stops entirely after `maxEntries`
//   directory entries, so a huge or deeply nested repo can't stall the scan.
const fs = require('node:fs/promises');
const path = require('node:path');

const toPosix = (p) => p.split(path.sep).join('/');

/**
 * @param {string} root
 * @param {Object} opts
 * @param {Set<string>} opts.fileNames    file names to report
 * @param {Iterable<string>} opts.ignoreDirs  folder names never entered
 * @param {Iterable<string>} opts.skipDirs    folder names entered, but their files are reported with `skipped: true`
 * @param {number} opts.maxDepth          deepest folder level entered (root = 0)
 * @param {number} opts.maxEntries        stop after this many directory entries
 * @returns {Promise<{
 *   files: {path: string, dir: string, name: string, skipped: boolean}[],
 *   stats: {filesSeen: number, dirsSeen: number, ignoredDirs: number},
 *   truncated: null | 'depth' | 'entries'
 * }>}  paths are relative to root with "/" separators; dir is '' for the root
 */
async function walkTree(root, { fileNames, ignoreDirs, skipDirs, maxDepth, maxEntries }) {
  const ignore = new Set(ignoreDirs);
  const skip = new Set(skipDirs);
  const files = [];
  const stats = { filesSeen: 0, dirsSeen: 0, ignoredDirs: 0 };
  let truncated = null;
  let entriesSeen = 0;

  // Breadth-first, so shallow (more important) files are found before any cap hits.
  const queue = [{ abs: root, depth: 0, skipped: false }];
  while (queue.length) {
    const { abs, depth, skipped } = queue.shift();
    const entries = await fs.readdir(abs, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      entriesSeen += 1;
      if (entriesSeen > maxEntries) {
        truncated = 'entries';
        return { files, stats, truncated };
      }

      const full = path.join(abs, entry.name);
      if (entry.isDirectory()) {
        if (ignore.has(entry.name)) {
          stats.ignoredDirs += 1;
        } else if (depth + 1 > maxDepth) {
          truncated = truncated || 'depth';
        } else {
          stats.dirsSeen += 1;
          queue.push({ abs: full, depth: depth + 1, skipped: skipped || skip.has(entry.name) });
        }
      } else if (entry.isFile()) {
        stats.filesSeen += 1;
        if (fileNames.has(entry.name)) {
          const rel = toPosix(path.relative(root, full));
          files.push({ path: rel, dir: path.posix.dirname(rel) === '.' ? '' : path.posix.dirname(rel), name: entry.name, skipped });
        }
      }
      // Anything else (symlinks, sockets, ...) is ignored.
    }
  }

  return { files, stats, truncated };
}

module.exports = { walkTree };
