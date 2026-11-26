// Estimates the version a Python requirement would install, for the fallback
// when there is no lockfile. Like npm, we take the LOWEST version allowed.
//
// Handles PEP 440 specifiers (==, ===, >=, ~=, <, >, !=, comma = "and") and
// Poetry's extras (^, ~, bare versions, "||" = "or").
// Results: { version } or { reason: 'unbounded' | 'invalid' }.

const CLAUSE = /^(===|==|~=|>=|<=|!=|>|<|\^|~|=)?v?([0-9][0-9A-Za-z.!+*-]*)$/;
// Operators whose version is the lowest allowed (a bare version means ==).
const LOWER_BOUND_OPS = new Set(['==', '===', '=', '>=', '~=', '^', '~']);

/** Compares versions by their numeric parts; good enough to pick a lowest/highest bound. */
function compareLoose(a, b) {
  const pa = a.split(/[.!+-]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.split(/[.!+-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

// ">=1.2,<2" -> lower bound 1.2 (the highest lower bound when there are several)
function lowestOfClauses(text) {
  const s = text.trim();
  if (s === '' || s === '*') return { reason: 'unbounded' };

  let lower = null;
  for (const raw of s.split(',')) {
    const clause = raw.replace(/\s+/g, '');
    if (!clause) continue;
    const m = CLAUSE.exec(clause);
    if (!m) return { reason: 'invalid' };
    const [, op = '==', version] = m;
    if (LOWER_BOUND_OPS.has(op)) {
      const v = version.replace(/(\.\*)+$/, '');   // "1.2.*" -> "1.2"
      if (v.includes('*')) return { reason: 'invalid' };
      if (!lower || compareLoose(v, lower) > 0) lower = v;
    }
  }
  return lower ? { version: lower } : { reason: 'unbounded' };
}

/** ">=2.0,<3" -> {version: '2.0'};  "^1.2 || ^2.0" (Poetry) -> {version: '1.2'} */
function pypiLowest(spec) {
  if (spec === null || spec === undefined) return { reason: 'unbounded' };
  if (typeof spec !== 'string') return { reason: 'invalid' };

  let best = null;
  let invalid = false;
  for (const alternative of spec.split('||')) {
    const r = lowestOfClauses(alternative);
    if (r.version) {
      if (!best || compareLoose(r.version, best) < 0) best = r.version;
    } else if (r.reason === 'invalid') {
      invalid = true;
    }
  }
  if (best) return { version: best };
  return { reason: invalid ? 'invalid' : 'unbounded' };
}

module.exports = { pypiLowest, compareLoose };
