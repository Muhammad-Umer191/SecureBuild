// Node's module lookup, applied to package-lock paths.
//
// A package installed at "node_modules/a/node_modules/b" that requires "d"
// loads the first of:
//   node_modules/a/node_modules/b/node_modules/d
//   node_modules/a/node_modules/d
//   node_modules/d
// So two versions of "d" can coexist, and each requirer gets the right one.

const parentOf = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');

/**
 * @param {Set<string>} paths  all install paths in the lockfile
 * @param {string} fromPath    install path of the requiring package ('' = project root)
 * @param {string} depName     e.g. "debug" or "@babel/core"
 * @returns {string|null}      install path of the copy that would be loaded
 */
function resolveNpmDep(paths, fromPath, depName) {
  let base = fromPath;
  for (;;) {
    // A folder named node_modules is never searched for its own node_modules.
    if (!base.endsWith('node_modules')) {
      const candidate = base ? `${base}/node_modules/${depName}` : `node_modules/${depName}`;
      if (paths.has(candidate)) return candidate;
    }
    if (!base) return null;
    base = parentOf(base);
  }
}

module.exports = { resolveNpmDep };
