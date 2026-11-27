// Parses poetry.lock (TOML) into components.
//
//   [[package]]
//   name = "requests"
//   version = "2.31.0"
//   groups = ["main"]              Poetry 2.x: which dependency groups need it
//   category = "main"              Poetry < 1.2: "main" or "dev"
//   [package.dependencies]
//   urllib3 = ">=1.21.1,<3"        what this package needs
//   [package.source]               present only for non-PyPI packages (git, path, url)
//
// poetry.lock doesn't say which packages are direct; pyproject.toml does.
const { ParseError } = require('../../common/errors');
const { pyprojectDeps } = require('./pyproject');
const { normalizePypiName } = require('./names');
const { isObject, keysOf } = require('../../common/objects');
const { skippedWarnings } = require('../../common/warnings');
const { byNameVersion } = require('../../common/components');

const NON_PYPI_SOURCES = new Set(['git', 'directory', 'file', 'url']);

/**
 * dev flag per package. Uses whatever the lockfile records; otherwise works it
 * out: a package reachable from a main (non-dev) dependency is not dev.
 */
function devFlags(pkgs, declared) {
  if (pkgs.some((p) => p.groups)) return pkgs.map((p) => !(p.groups || []).includes('main'));
  if (pkgs.some((p) => p.category)) return pkgs.map((p) => p.category === 'dev');
  if (!declared) return pkgs.map(() => false);

  const byName = new Map(pkgs.map((p) => [p.norm, p]));
  const reachable = new Set();
  const queue = declared.filter((d) => !d.dev).map((d) => normalizePypiName(d.name));
  while (queue.length) {
    const name = queue.shift();
    if (reachable.has(name) || !byName.has(name)) continue;
    reachable.add(name);
    queue.push(...byName.get(name).deps);
  }
  return pkgs.map((p) => !reachable.has(p.norm));
}

/**
 * @param {Object} lock          parsed poetry.lock
 * @param {Object} ctx
 * @param {string} ctx.source
 * @param {Object|null} [ctx.companion]  parsed pyproject.toml next to it
 * @returns {{components: Object[], warnings: string[]}}
 */
function parsePoetryLockfile(lock, { source, companion: pyproject = null }) {
  if (!isObject(lock) || !Array.isArray(lock.package)) {
    throw new ParseError(`${source}: no [[package]] entries found`);
  }

  const pkgs = [];
  const nonRegistry = [];
  for (const p of lock.package) {
    if (!isObject(p) || typeof p.name !== 'string' || typeof p.version !== 'string') continue;
    if (isObject(p.source) && NON_PYPI_SOURCES.has(p.source.type)) {
      nonRegistry.push(p.name);
      continue;
    }
    pkgs.push({
      name: p.name,
      norm: normalizePypiName(p.name),
      version: p.version,
      deps: keysOf(p.dependencies).map(normalizePypiName),
      groups: Array.isArray(p.groups) ? p.groups : null,
      category: typeof p.category === 'string' ? p.category : null,
    });
  }

  const declared = pyproject ? pyprojectDeps(pyproject) : null;
  // Without pyproject.toml, the best guess for "direct" is: nothing depends on it.
  const directNames = declared
    ? new Set(declared.map((d) => normalizePypiName(d.name)))
    : new Set(pkgs.map((p) => p.norm).filter((n) => !pkgs.some((q) => q.deps.includes(n))));

  const byName = new Map();
  pkgs.forEach((p) => byName.set(p.norm, [...(byName.get(p.norm) || []), p]));
  const dev = devFlags(pkgs, declared);

  const components = pkgs.map((p, i) => ({
    name: p.name,
    version: p.version,
    ecosystem: 'PyPI',
    direct: directNames.has(p.norm),
    dev: dev[i],
    license: null,
    dependsOn: [...new Set(p.deps)]
      .flatMap((d) => byName.get(d) || [])
      .map((q) => ({ name: q.name, version: q.version })),
    source,
    approximate: false,
  }));

  return {
    components: components.sort(byNameVersion),
    warnings: skippedWarnings(source, { nonRegistry }),
  };
}

module.exports = { parsePoetryLockfile };
