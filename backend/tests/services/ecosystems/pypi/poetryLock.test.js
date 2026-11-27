const { parse: parseToml } = require('smol-toml');
const { parsePoetryLockfile } = require('../../../../src/services/ecosystems/pypi/poetryLock');
const { ParseError } = require('../../../../src/services/common/errors');
const { toml } = require('../../fixtures');

const byName = (components) => new Map(components.map((c) => [c.name, c]));
const deps = (c) => c.dependsOn.map((d) => `${d.name}@${d.version}`);

describe('poetry.lock with groups (Poetry 2.x)', () => {
  const { components, warnings } = parsePoetryLockfile(toml('poetry-groups.lock'), {
    source: 'poetry.lock',
    companion: toml('pyproject-poetry.toml'),
  });
  const c = byName(components);

  test('lists every PyPI package with its exact version', () => {
    expect(components.map((x) => `${x.name}@${x.version}`)).toEqual([
      'certifi@2023.7.22', 'charset-normalizer@3.3.2', 'colorama@0.4.6', 'iniconfig@2.0.0',
      'pytest@7.4.0', 'requests@2.31.0', 'urllib3@2.0.7',
    ]);
    expect(components.every((x) => x.ecosystem === 'PyPI' && !x.approximate && x.license === null)).toBe(true);
  });

  test('direct deps come from pyproject.toml, matching names after normalization', () => {
    // pyproject says "Requests"; the lock says "requests"
    expect(components.filter((x) => x.direct).map((x) => x.name)).toEqual(['pytest', 'requests']);
  });

  test('dev comes from the groups field', () => {
    expect(components.filter((x) => x.dev).map((x) => x.name)).toEqual(['colorama', 'iniconfig', 'pytest']);
  });

  test('dependencies are linked by name', () => {
    expect(deps(c.get('requests'))).toEqual(['certifi@2023.7.22', 'charset-normalizer@3.3.2', 'urllib3@2.0.7']);
    expect(deps(c.get('pytest'))).toEqual(['colorama@0.4.6', 'iniconfig@2.0.0']);
  });

  test('git packages are skipped with a warning', () => {
    expect(c.has('mylib')).toBe(false);
    expect(warnings).toEqual(['poetry.lock: skipped 1 dependency not from the registry (git, file, link or URL): mylib']);
  });
});

describe('poetry.lock with category (Poetry < 1.2)', () => {
  test('dev comes from category = "dev"', () => {
    const lock = parseToml(`
[[package]]
name = "flask"
version = "2.0.0"
category = "main"
[[package]]
name = "pytest"
version = "6.0.0"
category = "dev"
`);
    const { components } = parsePoetryLockfile(lock, { source: 'poetry.lock' });
    expect(components.map((x) => [x.name, x.dev])).toEqual([['flask', false], ['pytest', true]]);
  });
});

describe('poetry.lock without groups or category', () => {
  const lock = parseToml(`
[[package]]
name = "Flask-Login"
version = "0.6.2"
[package.dependencies]
Flask = ">=1.0.4"
[[package]]
name = "flask"
version = "2.3.0"
[package.dependencies]
click = ">=8.1.3"
werkzeug = ">=2.3.0"
[[package]]
name = "click"
version = "8.1.7"
[[package]]
name = "werkzeug"
version = "2.3.7"
[[package]]
name = "pytest"
version = "7.4.0"
[package.dependencies]
pluggy = ">=0.12"
[[package]]
name = "pluggy"
version = "1.3.0"
`);
  const pyproject = parseToml(`
[project]
name = "x"
dependencies = ["flask_login>=0.6", "click"]
[tool.poetry.group.test.dependencies]
pytest = "*"
`);

  test('dev is worked out from the graph: reachable from main deps = not dev', () => {
    const { components } = parsePoetryLockfile(lock, { source: 'poetry.lock', companion: pyproject });
    expect(components.filter((x) => x.dev).map((x) => x.name)).toEqual(['pluggy', 'pytest']);
    expect(components.filter((x) => x.direct).map((x) => x.name)).toEqual(['click', 'Flask-Login', 'pytest']);
  });

  test('without pyproject.toml, direct = packages nothing depends on; nothing is dev', () => {
    const { components } = parsePoetryLockfile(lock, { source: 'poetry.lock' });
    expect(components.filter((x) => x.direct).map((x) => x.name)).toEqual(['Flask-Login', 'pytest']);
    expect(components.some((x) => x.dev)).toBe(false);
  });
});

describe('invalid input', () => {
  test('a lock with no [[package]] raises ParseError', () => {
    expect(() => parsePoetryLockfile(parseToml('[metadata]\nx = 1'), { source: 'poetry.lock' })).toThrow(ParseError);
  });
});
