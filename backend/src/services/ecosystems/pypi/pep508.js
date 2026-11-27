// Parses a Python requirement string (PEP 508), as found in requirements.txt
// and [project].dependencies:
//
//   requests[socks]>=2.0,<3 ; python_version > "3.8"
//   name    extras  spec       marker (when it applies; we scan it regardless)
//   mylib @ https://example.com/mylib.zip     direct URL: not on PyPI

const REQUIREMENT = /^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[([^\]]*)\])?\s*(.*)$/s;

/**
 * @param {string} text
 * @returns {{name: string, extras: string[], spec: string|null, url: string|null, marker: string|null}|null}
 *          null if it isn't a requirement
 */
function parsePep508(text) {
  if (typeof text !== 'string') return null;
  const [requirement, ...markerParts] = text.split(';');
  const m = REQUIREMENT.exec(requirement);
  if (!m) return null;

  const [, name, extrasText, restText] = m;
  const extras = extrasText ? extrasText.split(',').map((e) => e.trim()).filter(Boolean) : [];
  const marker = markerParts.join(';').trim() || null;
  let rest = restText.trim();

  if (rest.startsWith('@')) return { name, extras, spec: null, url: rest.slice(1).trim(), marker };
  if (rest.startsWith('(') && rest.endsWith(')')) rest = rest.slice(1, -1).trim();
  return { name, extras, spec: rest || null, url: null, marker };
}

module.exports = { parsePep508 };
