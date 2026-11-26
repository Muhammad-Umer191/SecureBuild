// Reads the declared (direct) dependencies from a parsed pyproject.toml.
// Used by poetryLock.js (to know which locked packages are direct/dev) and as
// the manifest fallback when there is no poetry.lock.
//
// Two styles exist, sometimes in the same file:
//   [project]
//   dependencies = ["requests>=2.31", "click"]          PEP 621 (strings)
//
//   [tool.poetry.dependencies]                          Poetry
//   python = "^3.9"                                     the interpreter, not a package
//   requests = "^2.31"
//   mylib = { git = "https://..." }                     not on PyPI
//   [tool.poetry.dev-dependencies]                      Poetry < 1.2 dev deps
//   [tool.poetry.group.test.dependencies]               Poetry >= 1.2 groups (non-main = dev)
const { isObject, entriesOf } = require('../../common/objects');
const { skippedWarnings } = require('../../common/warnings');
const { byNameVersion, createManifestCollector } = require('../../common/components');
const { parsePep508 } = require('./pep508');
const { pypiLowest } = require('./versions');

// Poetry value: "^1.2" | { version = "^1.2", optional = true } | { git = ... } | [ {...}, {...} ]
function readPoetryTable(table, dev, out) {
  for (const [name, raw] of entriesOf(table)) {
    if (name.toLowerCase() === 'python') continue;
    // A list means "different constraints per Python version"; take the first.
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (typeof value === 'string') {
      out.push({ name, spec: value, dev, nonRegistry: false });
    } else if (isObject(value)) {
      const nonRegistry = Boolean(value.git || value.path || value.url);
      const spec = !nonRegistry && typeof value.version === 'string' ? value.version : null;
      out.push({ name, spec, dev, nonRegistry });
    }
  }
}

/**
 * @param {Object} doc  parsed pyproject.toml
 * @returns {{name: string, spec: string|null, dev: boolean, nonRegistry: boolean}[]}
 */
function pyprojectDeps(doc) {
  const out = [];
  if (!isObject(doc)) return out;

  const project = isObject(doc.project) ? doc.project : null;
  if (project && Array.isArray(project.dependencies)) {
    for (const text of project.dependencies) {
      const req = parsePep508(text);
      if (req) out.push({ name: req.name, spec: req.spec, dev: false, nonRegistry: req.url !== null });
    }
  }

  const tool = isObject(doc.tool) ? doc.tool : null;
  const poetry = tool && isObject(tool.poetry) ? tool.poetry : null;
  if (poetry) {
    readPoetryTable(poetry.dependencies, false, out);
    readPoetryTable(poetry['dev-dependencies'], true, out);
    for (const [group, def] of entriesOf(poetry.group)) {
      if (isObject(def)) readPoetryTable(def.dependencies, group !== 'main', out);
    }
  }
  return out;
}

/**
 * Manifest fallback: direct dependencies with estimated (lowest) versions.
 * @param {Object} doc  parsed pyproject.toml
 * @param {{source: string}} ctx
 * @returns {{components: Object[], warnings: string[]}}
 */
function parsePyprojectManifest(doc, { source }) {
  const c = createManifestCollector('PyPI');
  for (const dep of pyprojectDeps(doc)) {
    const estimate = dep.nonRegistry ? { reason: 'nonRegistry' } : pypiLowest(dep.spec);
    c.add(dep.name, estimate, dep.dev, source);
  }
  return { components: c.components.sort(byNameVersion), warnings: skippedWarnings(source, c.skipped) };
}

module.exports = { pyprojectDeps, parsePyprojectManifest };
