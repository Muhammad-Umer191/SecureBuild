// Reads a dependency file from the clone, safely.
//
// - The path must stay inside the clone (also protects `-r ../../x` includes).
// - Only regular files are read (no symlinks), up to 20 MB.
// - Unreadable or malformed files raise ParseError, which callers turn into a
//   warning so one bad file doesn't stop the whole scan.
const fs = require('node:fs/promises');
const path = require('node:path');
const { parse: parseToml } = require('smol-toml');
const { ParseError } = require('../common/errors');

const MAX_BYTES = 20 * 1024 * 1024;

/** Absolute path of `relPath` inside `rootDir`; throws if it escapes. */
function resolveInside(rootDir, relPath) {
  const root = path.resolve(rootDir);
  const full = path.resolve(root, relPath);
  if (!full.startsWith(root + path.sep)) {
    throw new ParseError(`${relPath}: path is outside the repository`);
  }
  return full;
}

/**
 * @param {string} rootDir
 * @param {string} relPath   path relative to rootDir, "/" separators
 * @param {'json'|'toml'|'text'} format
 * @returns {Promise<any>} parsed object, or the text for 'text'
 */
async function readSourceFile(rootDir, relPath, format) {
  const full = resolveInside(rootDir, relPath);

  let stat;
  try {
    stat = await fs.lstat(full);
  } catch {
    throw new ParseError(`${relPath}: file not found`);
  }
  if (!stat.isFile()) throw new ParseError(`${relPath}: not a regular file`);
  if (stat.size > MAX_BYTES) throw new ParseError(`${relPath}: larger than 20 MB`);

  const text = (await fs.readFile(full, 'utf8')).replace(/^\uFEFF/, '');
  if (format === 'text') return text;
  try {
    return format === 'json' ? JSON.parse(text) : parseToml(text);
  } catch {
    throw new ParseError(`${relPath}: could not be read (invalid ${format.toUpperCase()})`);
  }
}

module.exports = { readSourceFile, resolveInside };
