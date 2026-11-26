// Last step of parseSources(): turns the raw components from every file into
// the final SBOM, one Component per package version, identified by its purl.
// It runs once all files are parsed, because duplicates can only be found
// across files (the same package in poetry.lock and requirements.txt).
//
//   1. canonical name   per ecosystem (PyPI: "Flask_Login" -> "flask-login")
//   2. purl             per ecosystem ("pkg:npm/%40babel/core@7.0.0")
//   3. merge duplicates the same purl from several files or sections
//   4. dependsOn        {name, version} links become purls; links to packages
//                       not in the list (e.g. skipped git deps) are dropped
//   5. sort by purl     same repo -> same output
//
// Ecosystem rules come from the registry, so nothing here is npm- or
// PyPI-specific.
const { registry: defaultRegistry } = require('../ecosystems');

/**
 * A package in the SBOM.
 * @typedef {Object} Component
 * @property {string} name          canonical name
 * @property {string} version
 * @property {string} ecosystem     'npm' | 'PyPI' (OSV spelling)
 * @property {string} purl          e.g. "pkg:npm/express@4.17.1"
 * @property {boolean} direct       listed by the project itself (in any file)
 * @property {boolean} dev          only needed for development (in every file)
 * @property {string|null} license
 * @property {string[]} dependsOn   purls of the packages this one needs
 * @property {string} source        dependency file it came from (first, alphabetically)
 * @property {boolean} approximate  version estimated from a manifest range (in every file)
 */

// How copies of the same package are combined:
// - direct: any copy is direct (someone lists it explicitly)
// - dev: every copy is dev (production use anywhere wins)
// - approximate: every copy is approximate (an exact lockfile entry wins)
function mergeInto(target, c, deps) {
  target.direct = target.direct || c.direct;
  target.dev = target.dev && c.dev;
  target.approximate = target.approximate && c.approximate;
  if (target.license === null && c.license) target.license = c.license;
  target.sources.add(c.source);
  deps.forEach((d) => target.deps.add(d));
}

/**
 * @param {Object[]} raw  components from parsers.parseSources
 * @param {Object} [opts]
 * @param {Object} [opts.registry]  ecosystem registry (default: npm + PyPI)
 * @returns {{components: Component[], stats: {raw: number, unique: number, duplicatesMerged: number, linksDropped: number}}}
 */
function normalizeComponents(raw, { registry = defaultRegistry } = {}) {
  const byPurl = new Map();

  for (const c of raw) {
    const eco = registry.get(c.ecosystem);
    if (!eco) throw new Error(`No ecosystem registered for "${c.ecosystem}" (package ${c.name})`);

    const name = eco.normalizeName(c.name);
    const purl = eco.purl(name, c.version);
    const deps = c.dependsOn.map((d) => eco.purl(eco.normalizeName(d.name), d.version));

    if (byPurl.has(purl)) {
      mergeInto(byPurl.get(purl), c, deps);
    } else {
      byPurl.set(purl, {
        name,
        version: c.version,
        ecosystem: c.ecosystem,
        purl,
        direct: c.direct,
        dev: c.dev,
        license: c.license || null,
        approximate: c.approximate,
        sources: new Set([c.source]),
        deps: new Set(deps),
      });
    }
  }

  let linksDropped = 0;
  const components = [...byPurl.values()]
    .sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0))
    .map(({ sources, deps, ...rest }) => {
      const dependsOn = [...deps].filter((d) => d !== rest.purl && byPurl.has(d)).sort();
      linksDropped += [...deps].filter((d) => d !== rest.purl).length - dependsOn.length;
      return {
        name: rest.name,
        version: rest.version,
        ecosystem: rest.ecosystem,
        purl: rest.purl,
        direct: rest.direct,
        dev: rest.dev,
        license: rest.license,
        dependsOn,
        source: [...sources].sort()[0],
        approximate: rest.approximate,
      };
    });

  return {
    components,
    stats: {
      raw: raw.length,
      unique: components.length,
      duplicatesMerged: raw.length - components.length,
      linksDropped,
    },
  };
}

module.exports = { normalizeComponents };
