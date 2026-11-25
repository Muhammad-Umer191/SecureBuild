// Decides which dependency files to scan, and explains what can't be scanned.
// Pure function: works on the file list from walkTree, no disk access.
//
// - A lockfile is always used (exact versions, full dependency tree).
// - A manifest is used only as a fallback when no lockfile covers it, and
//   its results are approximate (direct dependencies, estimated versions).
//   npm: covered by a package-lock.json in the same folder or any parent
//        (npm workspaces share the root lockfile). A yarn.lock or
//        pnpm-lock.yaml (unsupported) covers sub-folders only: its own
//        package.json is still used, but workspace packages below it are not,
//        so a big monorepo gives one approximate source instead of hundreds.
//   PyPI: covered by a poetry.lock in the same folder.
const { LOCKFILES, MANIFESTS, UNSUPPORTED_LOCKFILES } = require('./fileTypes');

const MAX_LISTED = 5;
const NPM_UNSUPPORTED = Object.keys(UNSUPPORTED_LOCKFILES).filter((n) => UNSUPPORTED_LOCKFILES[n] === 'npm');

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

/** Up to 5 messages are kept as they are; more are folded into one summary line. */
function capMessages(messages, summarize) {
  if (messages.length <= MAX_LISTED) return messages.map((m) => m.text);
  return [summarize(messages.map((m) => m.path))];
}

const listPaths = (paths) =>
  `${paths.slice(0, MAX_LISTED).join(', ')}${paths.length > MAX_LISTED ? `, and ${paths.length - MAX_LISTED} more` : ''}`;

/**
 * @param {{path: string, dir: string, name: string}[]} files  sorted by path
 * @returns {{
 *   sources: {path, filename, ecosystem, kind: 'lockfile'|'manifest', manifestPath: string|null}[],
 *   warnings: string[]
 * }}
 */
function selectSources(files) {
  const namesByDir = new Map();
  files.forEach((f) => {
    if (!namesByDir.has(f.dir)) namesByDir.set(f.dir, new Set());
    namesByDir.get(f.dir).add(f.name);
  });
  const dirHas = (dir, name) => namesByDir.get(dir)?.has(name) || false;
  const hasUnsupportedNpmLock = (dir) => NPM_UNSUPPORTED.some((name) => dirHas(dir, name));
  const coveredByLockfile = (dir, ecosystem) => {
    if (ecosystem !== 'npm') return dirHas(dir, 'poetry.lock');
    const dirs = selfAndParents(dir);
    return dirs.some((d) => dirHas(d, 'package-lock.json')) || dirs.slice(1).some(hasUnsupportedNpmLock);
  };
  // package.json files in folders below `dir` (workspace packages)
  const packagesBelow = (dir) =>
    files.filter((p) => p.name === 'package.json' && p.dir !== dir && (dir === '' || p.dir.startsWith(`${dir}/`))).length;

  const sources = [];
  const approximate = [];
  const unsupported = [];

  for (const f of files) {
    if (LOCKFILES[f.name]) {
      const { ecosystem, manifest } = LOCKFILES[f.name];
      sources.push({
        path: f.path,
        filename: f.name,
        ecosystem,
        kind: 'lockfile',
        manifestPath: dirHas(f.dir, manifest) ? join(f.dir, manifest) : null,
      });
    } else if (MANIFESTS[f.name]) {
      const ecosystem = MANIFESTS[f.name];
      if (!coveredByLockfile(f.dir, ecosystem)) {
        sources.push({ path: f.path, filename: f.name, ecosystem, kind: 'manifest', manifestPath: null });
        // Next to a yarn/pnpm lockfile, that lockfile's warning already explains this.
        if (ecosystem === 'npm' && hasUnsupportedNpmLock(f.dir)) continue;
        approximate.push({
          path: f.path,
          text: `${f.path}: no lockfile, so only direct dependencies are scanned and their versions are estimated`,
        });
      }
    } else if (UNSUPPORTED_LOCKFILES[f.name]) {
      const isNpm = UNSUPPORTED_LOCKFILES[f.name] === 'npm';
      const usingFallback = isNpm && dirHas(f.dir, 'package.json') && !coveredByLockfile(f.dir, 'npm');
      let text = usingFallback
        ? `${f.path} is not supported yet; using ${join(f.dir, 'package.json')} instead (approximate)`
        : `${f.path} is not supported yet; dependencies in ${where(f.dir)} were not scanned`;
      const workspaces = isNpm ? packagesBelow(f.dir) : 0;
      if (workspaces) text += `. ${workspaces} workspace packages under it were not scanned`;
      unsupported.push({ path: f.path, text });
    }
  }

  const warnings = [
    ...capMessages(approximate, (paths) =>
      `${paths.length} folders have no lockfile, so only direct dependencies are scanned and their versions are estimated: ${listPaths(paths)}`),
    ...capMessages(unsupported, (paths) =>
      `${paths.length} unsupported lockfiles (yarn/pnpm/Pipenv) were not read: ${listPaths(paths)}`),
  ];

  return { sources, warnings };
}

module.exports = { selectSources };
