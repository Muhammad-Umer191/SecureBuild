// package.json fallback, used when a project has no package-lock.json: reads
// the direct dependencies and estimates each version as the lowest one the
// range allows. Every component is approximate, with no dependency links.
const { ParseError } = require('../../common/errors');
const { isObject, entriesOf } = require('../../common/objects');
const { skippedWarnings } = require('../../common/warnings');
const { byNameVersion, createManifestCollector } = require('../../common/components');
const { npmLowest } = require('./versions');

const FIELDS = [
  ['dependencies', false],
  ['optionalDependencies', false],
  ['devDependencies', true],
];

/**
 * @param {Object} pkg  parsed package.json
 * @param {{source: string}} ctx
 * @returns {{components: Object[], warnings: string[]}}
 */
function parsePackageJson(pkg, { source }) {
  if (!isObject(pkg)) throw new ParseError(`${source}: not a package.json object`);
  const c = createManifestCollector('npm');
  for (const [field, dev] of FIELDS) {
    for (const [name, range] of entriesOf(pkg[field])) c.add(name, npmLowest(range), dev, source);
  }
  return { components: c.components.sort(byNameVersion), warnings: skippedWarnings(source, c.skipped) };
}

module.exports = { parsePackageJson };
