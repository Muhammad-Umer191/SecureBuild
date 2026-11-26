// Helpers for building raw components (the parsers' output).
//
// A raw component:
// { name, version, ecosystem, direct, dev, license, dependsOn: [{name, version}],
//   source, approximate }

const byNameVersion = (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version);

/**
 * Collects components for the manifest fallback (direct, approximate, no
 * dependency links) and the names that had to be skipped, by reason.
 * `add` takes a version estimate: {version} or {reason}.
 */
function createManifestCollector(ecosystem) {
  const components = [];
  const skipped = { nonRegistry: [], unbounded: [], invalid: [], options: [] };
  return {
    components,
    skipped,
    add(name, estimate, dev, source) {
      if (estimate.version) {
        components.push({
          name,
          version: estimate.version,
          ecosystem,
          direct: true,
          dev,
          license: null,
          dependsOn: [],
          source,
          approximate: true,
        });
      } else {
        skipped[estimate.reason].push(name);
      }
    },
  };
}

module.exports = { byNameVersion, createManifestCollector };
