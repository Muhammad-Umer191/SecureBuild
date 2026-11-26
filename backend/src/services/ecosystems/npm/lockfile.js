// Parses package-lock.json (v1, v2, v3) into components.
//
// v2/v3 have a flat "packages" map keyed by install path:
//   ""                                  the project itself (lists direct deps)
//   "node_modules/express"              an installed package
//   "node_modules/a/node_modules/b"     b nested under a (a second version of b)
//   "packages/ui"                       a workspace folder (local code, not a package)
//   "node_modules/ui" { link: true }    the link to that workspace folder
// v1 is converted to this shape first (lockfileV1.js).
const semver = require('semver');
const { ParseError } = require('../../common/errors');
const { resolveNpmDep } = require('./resolve');
const { convertV1 } = require('./lockfileV1');
const { isObject, entriesOf, keysOf } = require('../../common/objects');
const { skippedWarnings } = require('../../common/warnings');
const { byNameVersion } = require('../../common/components');

const ROOT_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const DEP_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];
const NON_REGISTRY = /^(git\+|git:|github:|gitlab:|bitbucket:|file:|link:)/;
const NM = 'node_modules/';

// "node_modules/a/node_modules/@s/b" -> "@s/b"
const installName = (p) => p.slice(p.lastIndexOf(NM) + NM.length);
// "node_modules/a/node_modules/b" -> "node_modules/a";  "node_modules/b" -> ""
const ownerOf = (p) => p.slice(0, p.lastIndexOf(NM)).replace(/\/$/, '');

/**
 * @param {Object} lock          parsed package-lock.json
 * @param {Object} ctx
 * @param {string} ctx.source    lockfile path in the repo
 * @param {Object|null} [ctx.companion]  parsed package.json next to it (needed for v1)
 * @returns {{components: Object[], warnings: string[]}}
 */
function parseNpmLockfile(lock, { source, companion = null }) {
  if (!isObject(lock)) throw new ParseError(`${source}: not a package-lock.json object`);
  if (isObject(lock.packages)) return parsePackagesMap(lock.packages, source);
  if (isObject(lock.dependencies)) return parsePackagesMap(convertV1(lock, companion), source);
  throw new ParseError(`${source}: unrecognised package-lock.json format`);
}

function parsePackagesMap(packagesObj, source) {
  const entries = new Map(entriesOf(packagesObj).filter(([, e]) => isObject(e)));
  const workspaceDirs = new Set([...entries.keys()].filter((p) => p !== '' && !p.includes(NM)));

  // Direct = listed by the project root or by one of its workspaces.
  const declarers = [entries.get(''), ...[...workspaceDirs].map((d) => entries.get(d))];
  const directNames = new Set(declarers.flatMap((e) => (e ? ROOT_FIELDS.flatMap((f) => keysOf(e[f])) : [])));

  const installed = new Map();
  const nonRegistry = [];
  for (const [p, e] of entries) {
    if (!p.includes(NM) || e.link === true || e.extraneous === true) continue;
    if (typeof e.version !== 'string') continue;
    const name = typeof e.name === 'string' ? e.name : installName(p);
    const resolved = typeof e.resolved === 'string' ? e.resolved : '';
    if (NON_REGISTRY.test(resolved) || !semver.valid(e.version)) {
      nonRegistry.push(name);
      continue;
    }
    installed.set(p, { name, version: e.version, entry: e });
  }

  const allPaths = new Set(entries.keys());
  const components = [...installed].map(([p, { name, version, entry }]) => {
    const owner = ownerOf(p);
    const dependsOn = [];
    const seen = new Set();
    for (const dep of DEP_FIELDS.flatMap((f) => keysOf(entry[f]))) {
      // Missing optional/peer deps and non-registry targets resolve to nothing.
      const target = installed.get(resolveNpmDep(allPaths, p, dep));
      const key = target && `${target.name}@${target.version}`;
      if (target && !seen.has(key)) {
        seen.add(key);
        dependsOn.push({ name: target.name, version: target.version });
      }
    }
    return {
      name,
      version,
      ecosystem: 'npm',
      direct: (owner === '' || workspaceDirs.has(owner)) && directNames.has(installName(p)),
      dev: entry.dev === true,
      license: typeof entry.license === 'string' ? entry.license : null,
      dependsOn,
      source,
      approximate: false,
    };
  });

  return {
    components: components.sort(byNameVersion),
    warnings: skippedWarnings(source, { nonRegistry }),
  };
}

module.exports = { parseNpmLockfile };
