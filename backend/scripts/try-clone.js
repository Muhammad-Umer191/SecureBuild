#!/usr/bin/env node
// Manual check of the clone service. Clones a repo, shows what was downloaded,
// then deletes it and confirms the temp folder is gone.
//
//   npm run try:clone -- https://github.com/expressjs/express
//   npm run try:clone -- https://github.com/expressjs/express --max-mb 1 --timeout 5000
const fs = require('node:fs/promises');
const { withClone, isValidRepoUrl, dirSize } = require('../src/services/clone');

function parseArgs(argv) {
  const [url, ...rest] = argv;
  const opts = {};
  for (let i = 0; i < rest.length; i += 2) {
    if (rest[i] === '--max-mb') opts.maxSizeMb = Number(rest[i + 1]);
    if (rest[i] === '--timeout') opts.timeoutMs = Number(rest[i + 1]);
  }
  return { url, opts };
}

async function main() {
  const { url, opts } = parseArgs(process.argv.slice(2));
  if (!url) {
    console.error('Usage: npm run try:clone -- <github-url> [--max-mb N] [--timeout MS]');
    process.exit(2);
  }

  console.log(`URL valid:    ${isValidRepoUrl(url)}`);
  const started = Date.now();
  let cloneDir;

  await withClone(url, async ({ dir, commitSha }) => {
    cloneDir = dir;
    const topLevel = (await fs.readdir(dir)).filter((n) => n !== '.git');

    console.log(`Cloned in:    ${((Date.now() - started) / 1000).toFixed(1)}s`);
    console.log(`Folder:       ${dir}`);
    console.log(`Commit SHA:   ${commitSha}`);
    console.log(`Size on disk: ${(await dirSize(dir) / 1024 / 1024).toFixed(2)} MB`);
    console.log(`Top level:    ${topLevel.slice(0, 15).join(', ')}${topLevel.length > 15 ? ', ...' : ''}`);
  }, opts);

  const stillThere = await fs.access(cloneDir).then(() => true, () => false);
  console.log(`Cleaned up:   ${stillThere ? 'NO - folder still exists!' : 'yes, temp folder removed'}`);
}

main().catch((err) => {
  console.error(`\nFailed: [${err.code || err.name}] ${err.message}`);
  if (err.permanent !== undefined) console.error(`Permanent:    ${err.permanent} (retrying ${err.permanent ? "won't" : 'might'} help)`);
  process.exit(1);
});
