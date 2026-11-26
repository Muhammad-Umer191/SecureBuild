// PyPI ecosystem descriptor (see ../index.js for the fields).
const { parsePoetryLockfile } = require('./poetryLock');
const { parsePyprojectManifest } = require('./pyproject');
const { parseRequirementsTxt } = require('./requirements');

module.exports = {
  ecosystem: 'PyPI',
  lockfiles: [
    { filename: 'poetry.lock', format: 'toml', companion: 'pyproject.toml', parse: parsePoetryLockfile },
  ],
  manifests: [
    { filename: 'pyproject.toml', format: 'toml', parse: parsePyprojectManifest },
    { filename: 'requirements.txt', format: 'text', parse: parseRequirementsTxt },
  ],
  unsupportedLockfiles: ['Pipfile.lock'],
  // Poetry has no workspaces: a poetry.lock covers only its own folder.
  lockfileScope: 'folder',
};
