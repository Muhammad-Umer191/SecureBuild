// Parsers module: turns the dependency files found by discovery into a list
// of raw components (the SBOM before purls and de-duplication).
//
// This module knows nothing about npm or Python: it looks each file up in the
// ecosystem registry, reads and decodes it safely, and hands it to that
// ecosystem's parse(). Import from here (require('./services/parsers')).
const { readSourceFile } = require('./readSourceFile');
const { ParseError } = require('../common/errors');
const { registry: defaultRegistry } = require('../ecosystems');

// Reads the manifest that sits next to a lockfile. It only refines the result
// (direct/dev flags), so a broken one is a warning, not a failure.
async function readCompanion(readFile, relPath, format, warnings) {
  if (!relPath) return null;
  try {
    return await readFile(relPath, format);
  } catch (err) {
    if (!(err instanceof ParseError)) throw err;
    warnings.push(`${err.message}; direct/dev flags for its lockfile are estimated`);
    return null;
  }
}

async function parseOne(rootDir, src, registry, warnings) {
  const entry = registry.lookup(src.filename);
  if (!entry || entry.kind === 'unsupported') {
    throw new ParseError(`${src.path}: no parser for ${src.filename}`);
  }
  const { eco, handler } = entry;
  const readFile = (relPath, format) => readSourceFile(rootDir, relPath, format);

  const content = await readFile(src.path, handler.format);
  let companion = null;
  if (handler.companion) {
    const companionFormat = eco.manifests.find((m) => m.filename === handler.companion).format;
    companion = await readCompanion(readFile, src.manifestPath, companionFormat, warnings);
  }
  return handler.parse(content, { source: src.path, companion, readFile });
}

/**
 * @param {string} rootDir  cloned repo folder
 * @param {Object[]} sources  from discovery: {path, filename, ecosystem, kind, manifestPath}
 * @param {Object} [opts]
 * @param {Object} [opts.registry]  ecosystem registry (default: npm + PyPI)
 * @returns {Promise<{components: Object[], warnings: string[]}>}
 *          A file that can't be parsed adds a warning; the others still count.
 */
async function parseSources(rootDir, sources, { registry = defaultRegistry } = {}) {
  const components = [];
  const warnings = [];
  for (const src of sources) {
    try {
      const result = await parseOne(rootDir, src, registry, warnings);
      components.push(...result.components);
      warnings.push(...result.warnings);
    } catch (err) {
      if (!(err instanceof ParseError)) throw err;
      warnings.push(err.message);
    }
  }
  return { components, warnings };
}

module.exports = { parseSources, ParseError };
