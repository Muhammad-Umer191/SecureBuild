// npm ecosystem descriptor (see ../index.js for the fields).
const { parseNpmLockfile } = require('./lockfile');
const { parsePackageJson } = require('./manifest');

module.exports = {
  ecosystem: 'npm',
  lockfiles: [
    { filename: 'package-lock.json', format: 'json', companion: 'package.json', parse: parseNpmLockfile },
  ],
  manifests: [
    { filename: 'package.json', format: 'json', parse: parsePackageJson },
  ],
  unsupportedLockfiles: ['yarn.lock', 'pnpm-lock.yaml'],
  // npm workspaces: one lockfile at the root covers every package below it.
  lockfileScope: 'subtree',
};
