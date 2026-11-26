// Ecosystem registry: everything that differs between package ecosystems
// (npm, PyPI, ...) lives in one folder per ecosystem, described by a
// descriptor. Discovery and the parsers only talk to this registry, so adding
// an ecosystem means adding a folder and one line in DEFAULT_ECOSYSTEMS.
//
// Descriptor fields:
//   ecosystem             name exactly as OSV.dev spells it ('npm', 'PyPI', 'Go', ...)
//   lockfiles             [{ filename, format, companion, parse }]
//                           exact versions of every installed package;
//                           companion = manifest file read alongside it (or null)
//   manifests             [{ filename, format, parse }]
//                           direct deps with version ranges; used only when no
//                           lockfile covers them (results are approximate)
//   unsupportedLockfiles  [filename]  recognised but not parsed: warning only
//   lockfileScope         'subtree' (covers sub-folders, e.g. workspaces) | 'folder'
//   normalizeName(name)   canonical spelling, used to match and de-duplicate
//   purl(name, version)   package URL, e.g. "pkg:npm/express@4.17.1"
//   compareVersions(a, b) <0, 0, >0 like a sort comparator; null if either isn't a valid version
//
//   format: 'json' | 'toml' | 'text' - the parsers read and decode the file
//   parse(content, { source, companion, readFile }) -> { components, warnings }
//     content    the decoded file;  companion: decoded companion manifest or null
//     readFile   (relPath, format) => Promise  safe reader for extra files (e.g. includes)
//     throws ParseError (common/errors.js) for a file it can't use
const npm = require('./npm');
const pypi = require('./pypi');

const DEFAULT_ECOSYSTEMS = [npm, pypi];
const FORMATS = new Set(['json', 'toml', 'text']);
const SCOPES = new Set(['subtree', 'folder']);

function validate(eco) {
  const where = `ecosystem "${eco && eco.ecosystem}"`;
  if (!eco || typeof eco.ecosystem !== 'string' || !eco.ecosystem) throw new Error('ecosystem descriptor needs a name');
  for (const field of ['lockfiles', 'manifests', 'unsupportedLockfiles']) {
    if (!Array.isArray(eco[field])) throw new Error(`${where}: ${field} must be an array`);
  }
  for (const h of [...eco.lockfiles, ...eco.manifests]) {
    if (typeof h.filename !== 'string' || typeof h.parse !== 'function' || !FORMATS.has(h.format)) {
      throw new Error(`${where}: each lockfile/manifest needs filename, format (json|toml|text) and parse()`);
    }
  }
  for (const l of eco.lockfiles) {
    if (l.companion && !eco.manifests.some((m) => m.filename === l.companion)) {
      throw new Error(`${where}: companion ${l.companion} must also be listed in manifests`);
    }
  }
  if (!SCOPES.has(eco.lockfileScope)) throw new Error(`${where}: lockfileScope must be 'subtree' or 'folder'`);
  for (const fn of ['normalizeName', 'purl', 'compareVersions']) {
    if (typeof eco[fn] !== 'function') throw new Error(`${where}: ${fn} must be a function`);
  }
}

/**
 * Builds the lookup tables. Throws if a descriptor is incomplete or two
 * ecosystems claim the same file name.
 * @param {Object[]} ecosystems
 */
function createRegistry(ecosystems = DEFAULT_ECOSYSTEMS) {
  const byFile = new Map();
  const byName = new Map();
  const claim = (filename, entry) => {
    if (byFile.has(filename)) {
      throw new Error(`${filename} is claimed by both ${byFile.get(filename).eco.ecosystem} and ${entry.eco.ecosystem}`);
    }
    byFile.set(filename, entry);
  };

  for (const eco of ecosystems) {
    validate(eco);
    if (byName.has(eco.ecosystem)) throw new Error(`ecosystem "${eco.ecosystem}" is registered twice`);
    byName.set(eco.ecosystem, eco);
    eco.lockfiles.forEach((handler) => claim(handler.filename, { eco, kind: 'lockfile', handler }));
    eco.manifests.forEach((handler) => claim(handler.filename, { eco, kind: 'manifest', handler }));
    eco.unsupportedLockfiles.forEach((filename) => claim(filename, { eco, kind: 'unsupported', handler: null }));
  }

  return {
    ecosystems,
    /** @returns {{eco, kind: 'lockfile'|'manifest'|'unsupported', handler}|undefined} */
    lookup: (filename) => byFile.get(filename),
    /** The descriptor for an ecosystem name ('npm', 'PyPI'), or undefined. */
    get: (ecosystem) => byName.get(ecosystem),
    /** Every file name discovery should look for. */
    knownFiles: new Set(byFile.keys()),
    /** Supported file names, lockfiles first, e.g. for "no dependency files found". */
    supportedFiles: [
      ...ecosystems.flatMap((e) => e.lockfiles.map((l) => l.filename)),
      ...ecosystems.flatMap((e) => e.manifests.map((m) => m.filename)),
    ],
  };
}

const registry = createRegistry();

module.exports = { registry, createRegistry, DEFAULT_ECOSYSTEMS };
