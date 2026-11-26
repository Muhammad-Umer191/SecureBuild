// Builds package URLs (purl), the standard package ID used by OSV, CycloneDX
// and most security tools:
//
//   pkg:<type>/<namespace>/<name>@<version>
//   pkg:npm/%40babel/core@7.0.0       namespace "@babel" (the "@" is encoded)
//   pkg:pypi/flask-login@0.6.2
//
// Each part is percent-encoded (spec: github.com/package-url/purl-spec), so
// characters like "@", "/", "+" inside a part can't be mistaken for separators.

/**
 * @param {string} type             e.g. 'npm', 'pypi'
 * @param {string|null} namespace   e.g. '@babel', or null
 * @param {string} name
 * @param {string} version
 */
function buildPurl(type, namespace, name, version) {
  const ns = namespace ? `${namespace.split('/').map(encodeURIComponent).join('/')}/` : '';
  return `pkg:${type}/${ns}${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

module.exports = { buildPurl };
