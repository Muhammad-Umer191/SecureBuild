// CycloneDX `components` (the packages) and `dependencies` (who needs whom).
const { spdxId } = require('./spdx');

const byPurl = (a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0);

/**
 * A license string from a lockfile, in the form the schema accepts:
 *   "MIT"                        -> { license: { id: 'MIT' } }       (a known SPDX ID)
 *   "(MIT OR Apache-2.0)"        -> { expression: '...' }            (an SPDX expression)
 *   "SEE LICENSE IN LICENSE.md"  -> { license: { name: '...' } }     (free text)
 */
function licensesOf(license) {
  if (typeof license !== 'string' || !license.trim()) return undefined;
  const text = license.trim();
  const id = spdxId(text);
  if (id) return [{ license: { id } }];
  if (/\s(OR|AND|WITH)\s/.test(text) || /^\(.*\)$/.test(text)) return [{ expression: text }];
  return [{ license: { name: text } }];
}

function toComponent(c) {
  const properties = [{ name: 'securebuild:source', value: c.source }];
  if (c.approximate) properties.push({ name: 'securebuild:approximate', value: 'true' });
  const licenses = licensesOf(c.license);
  return {
    type: 'library',
    'bom-ref': c.purl,
    name: c.name,
    version: c.version,
    purl: c.purl,
    scope: c.dev ? 'optional' : 'required',
    ...(licenses ? { licenses } : {}),
    properties,
  };
}

/**
 * The dependency graph. The repo depends on its direct packages; each package
 * on its `dependsOn`. A package with no dependencies gets an empty entry (the
 * spec's way of saying "none"). Approximate packages get NO entry: their
 * dependencies are unknown, not "none".
 */
function dependenciesOf(components, repoRef) {
  const sorted = [...components].sort(byPurl);
  return [
    { ref: repoRef, dependsOn: sorted.filter((c) => c.direct).map((c) => c.purl) },
    ...sorted.filter((c) => !c.approximate).map((c) => ({ ref: c.purl, dependsOn: [...c.dependsOn].sort() })),
  ];
}

/** @returns {{components: Object[], dependencies: Object[]}} */
function buildComponents(components, repoRef) {
  return {
    components: [...components].sort(byPurl).map(toComponent),
    dependencies: dependenciesOf(components, repoRef),
  };
}

module.exports = { buildComponents, licensesOf };
