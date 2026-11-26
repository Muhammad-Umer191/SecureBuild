// Converts an old (v1, npm 5-6) package-lock.json into the v2/v3 "packages"
// shape, so one code path handles every version.
//
// v1 is a nested tree: each entry's own "dependencies" are installed in its
// node_modules folder, and "requires" lists what it needs. That maps directly
// to v2 paths ("node_modules/a/node_modules/b") and v2 "dependencies".
const { isObject, entriesOf, keysOf } = require('../../common/objects');

const ROOT_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
// npm aliases: "npm:left-pad@1.3.0" -> installed as another name
const ALIAS = /^npm:((?:@[^/@]+\/)?[^/@]+)@(.+)$/;

/**
 * @param {Object} lock      parsed v1 lockfile
 * @param {Object|null} manifest  parsed package.json next to it (gives the direct deps)
 * @returns {Object} v2-style packages map (null prototype)
 */
function convertV1(lock, manifest) {
  const packages = Object.create(null);
  const required = new Set();

  // Iterative walk: a deeply nested (hostile) tree can't overflow the stack.
  const stack = [{ deps: lock.dependencies, base: '' }];
  while (stack.length) {
    const { deps, base } = stack.pop();
    for (const [installName, node] of entriesOf(deps)) {
      if (!isObject(node)) continue;
      const p = base ? `${base}/node_modules/${installName}` : `node_modules/${installName}`;

      let name;
      let { version } = node;
      const alias = typeof version === 'string' ? ALIAS.exec(version) : null;
      if (alias) [, name, version] = alias;

      packages[p] = {
        name,
        version,
        resolved: node.resolved,
        dev: node.dev === true,
        dependencies: isObject(node.requires) ? node.requires : undefined,
      };
      keysOf(node.requires).forEach((r) => required.add(r));
      if (isObject(node.dependencies)) stack.push({ deps: node.dependencies, base: p });
    }
  }

  // The root entry lists the direct dependencies. Without package.json, the
  // best guess is the top-level packages that nothing else requires.
  if (isObject(manifest)) {
    packages[''] = Object.fromEntries(ROOT_FIELDS.map((f) => [f, manifest[f]]));
  } else {
    const top = keysOf(lock.dependencies).filter((n) => !required.has(n));
    packages[''] = { dependencies: Object.fromEntries(top.map((n) => [n, '*'])) };
  }
  return packages;
}

module.exports = { convertV1 };
