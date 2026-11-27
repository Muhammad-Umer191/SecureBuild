// npm package names and purls.
//
// npm names are used exactly as written ("express", "@babel/core"): the
// registry has required lowercase names for years, and old mixed-case names
// are distinct packages, so nothing is rewritten.
const { buildPurl } = require('../../common/purl');

const normalizeNpmName = (name) => name;

/** "@babel/core", "7.0.0" -> "pkg:npm/%40babel/core@7.0.0" */
function npmPurl(name, version) {
  const slash = name.startsWith('@') ? name.indexOf('/') : -1;
  return slash === -1
    ? buildPurl('npm', null, name, version)
    : buildPurl('npm', name.slice(0, slash), name.slice(slash + 1), version);
}

module.exports = { normalizeNpmName, npmPurl };
