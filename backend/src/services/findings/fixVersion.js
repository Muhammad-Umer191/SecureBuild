// Which version fixes a flaw?
//
// An OSV record lists, per package, ranges of vulnerable versions as events:
//   { type: 'SEMVER', events: [{introduced: '0'}, {fixed: '4.17.12'}] }
//   -> every version from the first one up to (not including) 4.17.12 is affected
// A range can have several windows (one per release line):
//   introduced 1.0.0, fixed 1.2.5, introduced 2.0.0, fixed 2.1.1
//   -> 1.0.0 <= v < 1.2.5 and 2.0.0 <= v < 2.1.1 are affected
// We find the window containing OUR installed version; its `fixed` event is
// the fix. `last_affected` instead of `fixed` means no fix exists yet.
// GIT ranges use commit hashes, not versions, so they are skipped.
const { isObject } = require('../common/objects');

const VERSION_RANGE_TYPES = new Set(['SEMVER', 'ECOSYSTEM']);
const EVENT_KINDS = ['introduced', 'fixed', 'last_affected', 'limit'];

// The ecosystem's comparator, plus OSV's special "0" = lower than every version.
function versionComparator(eco) {
  return (a, b) => {
    if (a === b) return 0;
    if (a === '0') return -1;
    if (b === '0') return 1;
    return eco.compareVersions(a, b);   // null = can't compare
  };
}

function eventsOf(range) {
  return (Array.isArray(range.events) ? range.events : [])
    .map((e) => {
      if (!isObject(e)) return null;
      const kind = EVENT_KINDS.find((k) => typeof e[k] === 'string');
      return kind ? { kind, version: e[kind] } : null;
    })
    .filter(Boolean);
}

/**
 * Is `version` inside this range, and if so what fixes it?
 * @returns {{applies: boolean, fix?: string|null}|{invalid: true}}
 */
function evaluateRange(range, version, compare) {
  const events = eventsOf(range);
  let invalid = false;
  const sorted = [...events].sort((a, b) => {
    const c = compare(a.version, b.version);
    if (c === null) invalid = true;
    return c || 0;
  });
  if (invalid) return { invalid: true };

  let affected = false;
  let windowStart = -1;
  for (let i = 0; i < sorted.length; i += 1) {
    const { kind, version: at } = sorted[i];
    const c = compare(at, version);
    if (c === null) return { invalid: true };
    if (kind === 'introduced' && c <= 0) {
      affected = true;
      windowStart = i;
    } else if (kind === 'fixed' && c <= 0) {
      affected = false;
    } else if (kind === 'last_affected' && c < 0) {
      affected = false;
    }
  }
  if (!affected) return { applies: false };

  // The event that closes our window: `fixed` gives the fix; `last_affected`
  // or nothing at all means no fixed version exists.
  const closing = sorted.slice(windowStart + 1).find((e) => e.kind !== 'limit');
  return { applies: true, fix: closing && closing.kind === 'fixed' ? closing.version : null };
}

const isAffectedEntryFor = (entry, component, eco) => isObject(entry)
  && isObject(entry.package)
  && entry.package.ecosystem === component.ecosystem
  && typeof entry.package.name === 'string'
  && eco.normalizeName(entry.package.name) === eco.normalizeName(component.name);

/**
 * The fix one OSV record gives for this component's version.
 * @returns {{fix: string|null, invalid: boolean}}
 */
function fixForRecord(record, component, eco) {
  const compare = versionComparator(eco);
  const fixes = [];
  const laterFixes = [];   // fallback: fixed events above our version
  let applies = false;
  let invalid = false;

  const ranges = (Array.isArray(record.affected) ? record.affected : [])
    .filter((entry) => isAffectedEntryFor(entry, component, eco))
    .flatMap((entry) => (Array.isArray(entry.ranges) ? entry.ranges : []))
    .filter((r) => isObject(r) && VERSION_RANGE_TYPES.has(r.type));

  for (const range of ranges) {
    const result = evaluateRange(range, component.version, compare);
    if (result.invalid) {
      invalid = true;
      continue;
    }
    if (result.applies) {
      applies = true;
      if (result.fix) fixes.push(result.fix);
    }
    eventsOf(range)
      .filter((e) => e.kind === 'fixed' && compare(e.version, component.version) > 0)
      .forEach((e) => laterFixes.push(e.version));
  }

  // OSV matched the package but no range contains our version (it matched an
  // explicit `versions` list instead): the lowest fix above it is the best guess.
  const candidates = applies ? fixes : laterFixes;
  const pick = applies ? highest : lowest;
  return { fix: pick(candidates, compare), invalid };
}

function highest(versions, compare) {
  return versions.reduce((best, v) => (best === null || compare(v, best) > 0 ? v : best), null);
}

function lowest(versions, compare) {
  return versions.reduce((best, v) => (best === null || compare(v, best) < 0 ? v : best), null);
}

/**
 * The fix for one flaw (a group of alias records). When sources disagree,
 * the highest fix is used, so the upgrade is safe according to all of them.
 * @returns {{fix: string|null, invalid: boolean}}
 */
function fixForGroup(records, component, eco) {
  const results = records.map((r) => fixForRecord(r, component, eco));
  const known = results.map((r) => r.fix).filter(Boolean);
  return {
    fix: highest(known, versionComparator(eco)),
    invalid: results.some((r) => r.invalid),
  };
}

/**
 * One upgrade per package: the highest fix among its findings closes all the
 * fixable ones.
 * @param {(string|null)[]} fixes  fixedVersion of each finding on the package
 * @returns {{to: string|null, closes: number, unfixed: number}}
 */
function recommendUpgrade(fixes, eco) {
  const known = fixes.filter(Boolean);
  return {
    to: highest(known, versionComparator(eco)),
    closes: known.length,
    unfixed: fixes.length - known.length,
  };
}

module.exports = { evaluateRange, fixForRecord, fixForGroup, recommendUpgrade, versionComparator };
