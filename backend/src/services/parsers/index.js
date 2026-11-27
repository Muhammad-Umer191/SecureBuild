// Parsers module: turns the dependency files found by discovery into the
// SBOM, one Component per package version, identified by its purl.
//
//   1. each file      looked up in the ecosystem registry, read and decoded
//                     safely, and handed to that ecosystem's parse()
//   2. all files      combined by normalizeComponents(): purls, canonical
//                     names, duplicates merged (see normalizeComponents.js)
//
// This module knows nothing about npm or Python; that lives in the ecosystem
// folders. Import from here (require('./services/parsers')).
const { readSourceFile } = require('./readSourceFile');
const { normalizeComponents } = require('./normalizeComponents');
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
 * @returns {Promise<{
 *   components: import('./normalizeComponents').Component[],
 *   warnings: string[],
 *   stats: {raw: number, unique: number, duplicatesMerged: number, linksDropped: number}
 * }>}  A file that can't be parsed adds a warning; the others still count.
 */
async function parseSources(rootDir, sources, { registry = defaultRegistry } = {}) {
  const raw = [];
  const warnings = [];
  for (const src of sources) {
    try {
      const result = await parseOne(rootDir, src, registry, warnings);
      raw.push(...result.components);
      warnings.push(...result.warnings);
    } catch (err) {
      if (!(err instanceof ParseError)) throw err;
      warnings.push(err.message);
    }
  }
  const { components, stats } = normalizeComponents(raw, { registry });
  return { components, warnings, stats };
}

module.exports = { parseSources, ParseError };
