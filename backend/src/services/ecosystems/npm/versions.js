// Estimates the version an npm range would install, for the fallback when
// there is no lockfile. We take the LOWEST version the range allows: it is a
// version the project accepts, and the one most likely to still contain old
// bugs, so the scan errs on the side of reporting.
//
// Results: { version } or { reason } where reason is
//   'unbounded'    no lower bound (*, latest, <3): can't pick a version
//   'nonRegistry'  git/file/URL/workspace spec: not a registry package
//   'invalid'      not a range we understand
const semver = require('semver');

const NPM_NON_REGISTRY = /^(git\+|git:|github:|gitlab:|bitbucket:|file:|link:|workspace:|npm:|https?:)/;
const NPM_ANY = new Set(['', '*', 'x', 'X', 'latest']);

/** "^4.17.0" -> {version: '4.17.0'};  "*" -> {reason: 'unbounded'} */
function npmLowest(range) {
  if (typeof range !== 'string') return { reason: 'invalid' };
  const r = range.trim();
  // Ranges never contain "/"; "user/repo" is GitHub shorthand, "./x" a path.
  if (NPM_NON_REGISTRY.test(r) || r.includes('/')) return { reason: 'nonRegistry' };
  if (NPM_ANY.has(r)) return { reason: 'unbounded' };

  let min;
  try {
    min = semver.minVersion(r);
  } catch {
    return { reason: 'invalid' };   // e.g. a dist-tag like "next"
  }
  if (!min) return { reason: 'invalid' };
  // "<2" gives 0.0.0, which no one actually installs: treat as no lower bound.
  if (min.version === '0.0.0' && !r.includes('0.0.0')) return { reason: 'unbounded' };
  return { version: min.version };
}

module.exports = { npmLowest };
