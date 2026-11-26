const { parse: parseToml } = require('smol-toml');
const { parsePyprojectManifest } = require('../../../../src/services/ecosystems/pypi/pyproject');

const summary = (components) => components.map((c) => `${c.name}@${c.version}${c.dev ? ' (dev)' : ''}`);

describe('pyproject.toml fallback', () => {
  test('Poetry style, with groups and a git dependency', () => {
    const doc = parseToml(`
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.31"
rich = { version = ">=13.0", optional = true }
mylib = { git = "https://github.com/u/mylib.git" }
anything = "*"
[tool.poetry.group.dev.dependencies]
pytest = "^7.4"
`);
    const { components, warnings } = parsePyprojectManifest(doc, { source: 'pyproject.toml' });
    expect(summary(components)).toEqual(['pytest@7.4 (dev)', 'requests@2.31', 'rich@13.0']);
    expect(components.every((c) => c.ecosystem === 'PyPI' && c.approximate)).toBe(true);
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toMatch(/not from the registry.*: mylib$/);
    expect(warnings[1]).toMatch(/no minimum version.*: anything$/);
  });

  test('PEP 621 [project] style', () => {
    const doc = parseToml('[project]\nname = "x"\ndependencies = ["Django>=4.2,<5", "click"]');
    const { components, warnings } = parsePyprojectManifest(doc, { source: 'pyproject.toml' });
    expect(summary(components)).toEqual(['Django@4.2']);
    expect(warnings[0]).toMatch(/no minimum version.*: click$/);
  });
});
