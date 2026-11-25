#!/usr/bin/env node
// Manual check of the discovery module: clones a repo, lists the dependency
// files the scanner would read, and prints the warnings.
//
//   npm run try:discover -- https://github.com/python-poetry/poetry
//   npm run try:discover -- https://github.com/python-poetry/poetry --all   (don't skip test folders)
const { withClone } = require('../src/services/clone');
const { discoverDependencyFiles } = require('../src/services/discovery');

async function main() {
  const [url, ...flags] = process.argv.slice(2);
  if (!url) {
    console.error('Usage: npm run try:discover -- <github-url> [--all]');
    process.exit(2);
  }
  const opts = flags.includes('--all') ? { skipDirs: [] } : {};

  await withClone(url, async ({ dir, commitSha }) => {
    const { sources, warnings, stats } = await discoverDependencyFiles(dir, opts);

    console.log(`Commit:   ${commitSha}`);
    console.log(`Searched: ${stats.filesSeen} files in ${stats.dirsSeen} folders (${stats.ignoredDirs} folders ignored)\n`);

    console.log(`Sources (${sources.length}):`);
    if (!sources.length) console.log('  (none)');
    sources.forEach((s) => {
      const kind = s.kind === 'lockfile' ? 'lockfile (exact)' : 'manifest (approximate)';
      const manifest = s.manifestPath ? `  + ${s.manifestPath}` : '';
      console.log(`  ${s.ecosystem.padEnd(5)} ${kind.padEnd(23)} ${s.path}${manifest}`);
    });

    console.log(`\nWarnings (${warnings.length}):`);
    if (!warnings.length) console.log('  (none)');
    warnings.forEach((w) => console.log(`  - ${w}`));
  });
}

main().catch((err) => {
  console.error(`\nFailed: [${err.code || err.name}] ${err.message}`);
  process.exit(1);
});
