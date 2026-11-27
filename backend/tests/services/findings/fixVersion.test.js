const { fixForRecord, fixForGroup, recommendUpgrade } = require('../../../src/services/findings/fixVersion');
const { registry } = require('../../../src/services/ecosystems');

const npm = registry.get('npm');
const pypi = registry.get('PyPI');

const comp = (name, version, ecosystem = 'npm') => ({ name, version, ecosystem });
const range = (type, ...events) => ({ type, events });
const record = (pkg, ecosystem, ...ranges) => ({ id: 'X', affected: [{ package: { name: pkg, ecosystem }, ranges }] });
const fixOf = (rec, component, eco = npm) => fixForRecord(rec, component, eco).fix;

describe('fixForRecord: one range', () => {
  const rec = record('lodash', 'npm', range('SEMVER', { introduced: '0' }, { fixed: '4.17.12' }));
  test.each([
    ['4.17.11', '4.17.12'],   // inside the range: fixed in 4.17.12
    ['0.1.0', '4.17.12'],     // "0" means from the very first version
  ])('installed %s -> fix %s', (version, fix) => {
    expect(fixOf(rec, comp('lodash', version))).toBe(fix);
  });

  test('an installed version at or past the fix: the record does not apply, no later fix -> null', () => {
    expect(fixOf(rec, comp('lodash', '4.17.12'))).toBeNull();
    expect(fixOf(rec, comp('lodash', '4.17.21'))).toBeNull();
  });
});

describe('fixForRecord: several windows (release lines)', () => {
  const rec = record('pkg', 'npm', range('SEMVER',
    { introduced: '1.0.0' }, { fixed: '1.2.5' }, { introduced: '2.0.0' }, { fixed: '2.1.1' }));
  test.each([
    ['1.1.0', '1.2.5'],
    ['2.0.3', '2.1.1'],
  ])('installed %s -> fix %s', (version, fix) => {
    expect(fixOf(rec, comp('pkg', version))).toBe(fix);
  });

  test('events given out of order are sorted first', () => {
    const shuffled = record('pkg', 'npm', range('SEMVER',
      { fixed: '2.1.1' }, { introduced: '2.0.0' }, { fixed: '1.2.5' }, { introduced: '1.0.0' }));
    expect(fixOf(shuffled, comp('pkg', '2.0.3'))).toBe('2.1.1');
  });
});

describe('fixForRecord: no fix', () => {
  test('last_affected means no fixed version exists', () => {
    const rec = record('pkg', 'npm', range('SEMVER', { introduced: '0' }, { last_affected: '4.5.1' }));
    expect(fixOf(rec, comp('pkg', '4.0.0'))).toBeNull();
  });

  test('a range with only "introduced" is open-ended: no fix', () => {
    const rec = record('babel-traverse', 'npm', range('SEMVER', { introduced: '0' }));
    expect(fixOf(rec, comp('babel-traverse', '6.26.0'))).toBeNull();
  });

  test('GIT ranges (commit hashes) are ignored', () => {
    const rec = record('pkg', 'npm', range('GIT', { introduced: 'abc123' }, { fixed: 'def456' }));
    expect(fixOf(rec, comp('pkg', '1.0.0'))).toBeNull();
  });
});

describe('fixForRecord: picking the right package', () => {
  test('only the affected entry for our package counts (lodash vs lodash-es)', () => {
    const rec = {
      id: 'GHSA-jf85-cpcp-j695',
      affected: [
        { package: { name: 'lodash-es', ecosystem: 'npm' }, ranges: [range('SEMVER', { introduced: '0' }, { fixed: '4.17.14' })] },
        { package: { name: 'lodash', ecosystem: 'npm' }, ranges: [range('SEMVER', { introduced: '0' }, { fixed: '4.17.12' })] },
        { package: { name: 'lodash', ecosystem: 'PyPI' }, ranges: [range('ECOSYSTEM', { introduced: '0' }, { fixed: '9.9' })] },
      ],
    };
    expect(fixOf(rec, comp('lodash', '4.17.11'))).toBe('4.17.12');
  });

  test('PyPI names match after normalization', () => {
    const rec = record('Flask_Login', 'PyPI', range('ECOSYSTEM', { introduced: '0' }, { fixed: '0.6.3' }));
    expect(fixOf(rec, comp('flask-login', '0.6.2', 'PyPI'), pypi)).toBe('0.6.3');
  });
});

describe('fixForRecord: PyPI version order (PEP 440)', () => {
  const rec = record('django', 'PyPI', range('ECOSYSTEM', { introduced: '0' }, { fixed: '3.2' }));
  test.each([
    ['3.2rc1', '3.2'],        // a release candidate comes BEFORE 3.2, so it is still vulnerable
    ['3.1.9.post1', '3.2'],   // a post-release of 3.1.9 is still before 3.2
    ['3.2', null],
    ['3.2.post1', null],      // a post-release comes AFTER 3.2: already fixed
  ])('installed %s -> %p', (version, fix) => {
    expect(fixOf(rec, comp('django', version, 'PyPI'), pypi)).toBe(fix);
  });
});

describe('fixForRecord: fallback and bad data', () => {
  test('no window contains our version: the lowest fix above it is used', () => {
    // OSV can match through an explicit `versions` list; the ranges then don't contain us.
    const rec = record('pkg', 'npm', range('SEMVER', { introduced: '2.0.0' }, { fixed: '2.0.5' }, { introduced: '3.0.0' }, { fixed: '3.1.0' }));
    expect(fixOf(rec, comp('pkg', '1.0.0'))).toBe('2.0.5');
  });

  test('versions that cannot be compared are flagged, not guessed', () => {
    const rec = record('pkg', 'npm', range('SEMVER', { introduced: '0' }, { fixed: 'not-a-version' }));
    expect(fixForRecord(rec, comp('pkg', '1.0.0'), npm)).toEqual({ fix: null, invalid: true });
  });
});

describe('fixForGroup and recommendUpgrade', () => {
  test('when alias records disagree, the highest fix is used (safe for both)', () => {
    const a = record('pkg', 'npm', range('SEMVER', { introduced: '0' }, { fixed: '1.2.0' }));
    const b = record('pkg', 'npm', range('SEMVER', { introduced: '0' }, { fixed: '1.3.0' }));
    expect(fixForGroup([a, b], comp('pkg', '1.0.0'), npm)).toEqual({ fix: '1.3.0', invalid: false });
  });

  test('one upgrade per package: the highest fix, with unfixed findings counted', () => {
    expect(recommendUpgrade(['4.17.12', '4.18.0', null, '4.17.21'], npm)).toEqual({ to: '4.18.0', closes: 3, unfixed: 1 });
    expect(recommendUpgrade([null, null], npm)).toEqual({ to: null, closes: 0, unfixed: 2 });
  });

  test('PyPI upgrades use PEP 440 order (2.10 > 2.9)', () => {
    expect(recommendUpgrade(['2.9', '2.10'], pypi).to).toBe('2.10');
  });
});
