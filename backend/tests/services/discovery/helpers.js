// Builds small fake repos on disk for discovery tests.
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

/** Creates a temp folder with the given files: { 'a/package.json': '{}' }. */
async function makeRepo(fileMap = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'sb-discover-'));
  for (const [rel, content] of Object.entries(fileMap)) {
    const full = path.join(root, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content);
  }
  return root;
}

const removeRepo = (root) => fs.rm(root, { recursive: true, force: true });

module.exports = { makeRepo, removeRepo };
