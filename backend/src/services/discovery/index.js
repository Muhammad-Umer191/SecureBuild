// Discovery module: finds the dependency files (lockfiles, or manifests as a
// fallback) in a cloned repo. Import from here (require('./services/discovery')).
const { discoverDependencyFiles } = require('./discoverDependencyFiles');
const { DEFAULT_SKIP_DIRS, DEFAULT_IGNORE_DIRS } = require('./fileTypes');

module.exports = { discoverDependencyFiles, DEFAULT_SKIP_DIRS, DEFAULT_IGNORE_DIRS };
