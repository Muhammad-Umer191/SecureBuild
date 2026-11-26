// Finds the files in a cloned repo that describe its dependencies.
//
//   walkTree        list known file names safely (no symlinks, capped)
//   size check      drop files too big to parse
//   selectSources   lockfile vs manifest fallback, plus warnings
//
// Reads names and sizes only, never file contents.
const fs = require('node:fs/promises');
const path = require('node:path');
const { walkTree } = require('./walkTree');
const { selectSources } = require('./selectSources');
const { DEFAULT_IGNORE_DIRS, DEFAULT_SKIP_DIRS } = require('./fileTypes');
const { registry: defaultRegistry } = require('../ecosystems');

/**
 * @param {string} rootDir  Cloned repo folder
 * @param {Object} [opts]
 * @param {number} [opts.maxFileSizeMb=20]
 * @param {number} [opts.maxDepth=20]
 * @param {number} [opts.maxEntries=100000]
 * @param {string[]} [opts.skipDirs]    test/example folder names (files there are skipped and counted)
 * @param {string[]} [opts.ignoreDirs]  folder names never entered
 * @param {Object} [opts.registry]      ecosystem registry (default: npm + PyPI)
 * @returns {Promise<{sources: Object[], warnings: string[], stats: Object}>}
 */
async function discoverDependencyFiles(rootDir, opts = {}) {
  const {
    maxFileSizeMb = 20,
    maxDepth = 20,
    maxEntries = 100_000,
    skipDirs = DEFAULT_SKIP_DIRS,
    ignoreDirs = DEFAULT_IGNORE_DIRS,
    registry = defaultRegistry,
  } = opts;
  const maxBytes = maxFileSizeMb * 1024 * 1024;
  const warnings = [];

  const { files, stats, truncated } = await walkTree(rootDir, {
    fileNames: registry.knownFiles, ignoreDirs, skipDirs, maxDepth, maxEntries,
  });

  const skippedCount = files.filter((f) => f.skipped).length;
  if (skippedCount) {
    warnings.push(`${skippedCount} dependency files inside test/example folders were skipped`);
  }

  // A file too big to parse safely is dropped. If it was a lockfile, the
  // manifest next to it becomes the fallback.
  const usable = [];
  for (const f of files.filter((x) => !x.skipped)) {
    const { size } = await fs.lstat(path.join(rootDir, f.path));
    if (size > maxBytes) {
      warnings.push(`${f.path} is larger than ${maxFileSizeMb} MB and was skipped`);
    } else {
      usable.push(f);
    }
  }

  usable.sort((a, b) => a.path.localeCompare(b.path));
  const { sources, warnings: sourceWarnings } = selectSources(usable, registry);
  warnings.push(...sourceWarnings);

  if (truncated === 'depth') {
    warnings.push(`Folders deeper than ${maxDepth} levels were not searched; results may be incomplete`);
  } else if (truncated === 'entries') {
    warnings.push(`Search stopped after ${maxEntries} entries; results may be incomplete`);
  }
  if (!sources.length) {
    warnings.push(`No dependency files found (${registry.supportedFiles.join(', ')})`);
  }

  return { sources, warnings, stats };
}

module.exports = { discoverDependencyFiles };
