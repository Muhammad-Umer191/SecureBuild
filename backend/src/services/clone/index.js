// Clone module: safely downloads a public GitHub repo into a temp folder.
// Import from here (require('./services/clone')); the other files are internals.
const { dirSize } = require('./dirSize');

module.exports = { ...require('./repoCloneService'), dirSize };
