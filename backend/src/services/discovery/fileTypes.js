// File and folder names discovery knows about.

/** Lockfiles: exact versions of every installed package. */
const LOCKFILES = {
  'package-lock.json': { ecosystem: 'npm', manifest: 'package.json' },
  'poetry.lock': { ecosystem: 'PyPI', manifest: 'pyproject.toml' },
};

/** Manifests: direct dependencies with version ranges. Used only when no lockfile covers them. */
const MANIFESTS = {
  'package.json': 'npm',
  'pyproject.toml': 'PyPI',
  'requirements.txt': 'PyPI',
};

/** Lockfiles we can't parse yet. They only produce a warning. */
const UNSUPPORTED_LOCKFILES = {
  'yarn.lock': 'npm',
  'pnpm-lock.yaml': 'npm',
  'Pipfile.lock': 'PyPI',
};

/** Every file name the walk should report. */
const KNOWN_FILES = new Set([
  ...Object.keys(LOCKFILES),
  ...Object.keys(MANIFESTS),
  ...Object.keys(UNSUPPORTED_LOCKFILES),
]);

/** Never entered: installed packages, virtualenvs, caches, git internals. */
const DEFAULT_IGNORE_DIRS = ['.git', 'node_modules', 'vendor', 'venv', '.venv', '__pycache__', '.tox'];

/**
 * Entered only to count what is skipped: dependency files here belong to
 * tests, demos or docs samples, not to the real project.
 */
const DEFAULT_SKIP_DIRS = [
  'test', 'tests', '__tests__', 'fixtures', '__fixtures__', 'testdata',
  'examples', 'playground', 'demo', 'demos', 'sample', 'samples',
];

module.exports = {
  LOCKFILES,
  MANIFESTS,
  UNSUPPORTED_LOCKFILES,
  KNOWN_FILES,
  DEFAULT_IGNORE_DIRS,
  DEFAULT_SKIP_DIRS,
};
