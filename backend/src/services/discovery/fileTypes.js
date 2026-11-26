// Folder names discovery treats specially. Which FILE names to look for comes
// from the ecosystem registry (services/ecosystems).

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

module.exports = { DEFAULT_IGNORE_DIRS, DEFAULT_SKIP_DIRS };
