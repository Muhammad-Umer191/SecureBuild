// Decides which dependency files to scan, and explains what can't be scanned.
// Pure function: works on the file list from walkTree, no disk access. All
// ecosystem knowledge comes from the registry.
//
// - A lockfile is always used (exact versions, full dependency tree).
// - A manifest is used only as a fallback when no lockfile of its ecosystem
//   covers it; its results are approximate (direct deps, estimated versions).
//   A lockfile covers manifests in its own folder, and also in sub-folders
//   when the ecosystem's lockfileScope is 'subtree' (npm workspaces).
// - An unsupported lockfile (e.g. yarn.lock) can't be read, so the manifests
//   next to it are used instead. With scope 'subtree' it still covers the
//   sub-folders, so a big monorepo gives one approximate source instead of
//   hundreds of workspace packages.
const { capMessages, listNames } = require('../common/warnings');
const { registry: defaultRegistry } = require('../ecosystems');

const join = (dir, name) => (dir ? `${dir}/${name}` : name);
const where = (dir) => (dir ? `${dir}/` : 'the repo root');

// 'a/b' -> ['a/b', 'a', '']  ('' is the repo root)
function selfAndParents(dir) {
  const dirs = [dir];
  let d = dir;
  while (d) {
    d = d.includes('/') ? d.slice(0, d.lastIndexOf('/')) : '';
    dirs.push(d);
  }
  return dirs;
}

const isBelow = (dir, parent) => dir !== parent && (parent === '' || dir.startsWith(`${parent}/`));

/**
 * @param {{path: string, dir: string, name: string}[]} files  sorted by path
 * @param {Object} [registry]  ecosystem registry
 * @returns {{
 *   sources: {path, filename, ecosystem, kind: 'lockfile'|'manifest', manifestPath: string|null}[],
 *   warnings: string[]
 * }}
 */
function selectSources(files, registry = defaultRegistry) {
  const namesByDir = new Map();
  files.forEach((f) => {
    if (!namesByDir.has(f.dir)) namesByDir.set(f.dir, new Set());
    namesByDir.get(f.dir).add(f.name);
  });
  const dirHasAny = (dir, names) => names.some((n) => namesByDir.get(dir)?.has(n));
  const lockNames = (eco) => eco.lockfiles.map((l) => l.filename);
  const manifestNames = (eco) => eco.manifests.map((m) => m.filename);

  const coveredByLockfile = (dir, eco) => {
    if (dirHasAny(dir, lockNames(eco))) return true;
    if (eco.lockfileScope !== 'subtree') return false;
    const parents = selfAndParents(dir).slice(1);
    return parents.some((d) => dirHasAny(d, [...lockNames(eco), ...eco.unsupportedLockfiles]));
  };

  const sources = [];
  const approximate = [];
  const unsupported = [];

  for (const f of files) {
    const entry = registry.lookup(f.name);
    if (!entry) continue;
    const { eco, kind, handler } = entry;

    if (kind === 'lockfile') {
      sources.push({
        path: f.path,
        filename: f.name,
        ecosystem: eco.ecosystem,
        kind: 'lockfile',
        manifestPath: handler.companion && dirHasAny(f.dir, [handler.companion]) ? join(f.dir, handler.companion) : null,
      });
    } else if (kind === 'manifest') {
      if (coveredByLockfile(f.dir, eco)) continue;
      sources.push({ path: f.path, filename: f.name, ecosystem: eco.ecosystem, kind: 'manifest', manifestPath: null });
      // Next to an unsupported lockfile, that lockfile's warning already explains this.
      if (dirHasAny(f.dir, eco.unsupportedLockfiles)) continue;
      approximate.push({
        path: f.path,
        text: `${f.path}: no lockfile, so only direct dependencies are scanned and their versions are estimated`,
      });
    } else {
      const fallbacks = coveredByLockfile(f.dir, eco)
        ? []
        : manifestNames(eco).filter((m) => dirHasAny(f.dir, [m])).map((m) => join(f.dir, m));
      let text = fallbacks.length
        ? `${f.path} is not supported yet; using ${fallbacks.join(', ')} instead (approximate)`
        : `${f.path} is not supported yet; dependencies in ${where(f.dir)} were not scanned`;
      if (eco.lockfileScope === 'subtree') {
        const below = files.filter((p) => manifestNames(eco).includes(p.name) && isBelow(p.dir, f.dir)).length;
        if (below) text += `. ${below} workspace packages under it were not scanned`;
      }
      unsupported.push({ path: f.path, text });
    }
  }

  const warnings = [
    ...capMessages(approximate, (paths) =>
      `${paths.length} folders have no lockfile, so only direct dependencies are scanned and their versions are estimated: ${listNames(paths)}`),
    ...capMessages(unsupported, (paths) =>
      `${paths.length} unsupported lockfiles were not read: ${listNames(paths)}`),
  ];

  return { sources, warnings };
}

module.exports = { selectSources };
