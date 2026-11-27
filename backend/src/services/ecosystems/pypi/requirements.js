// requirements.txt fallback: one PEP 508 requirement per line, plus pip
// options. Versions are estimated (lowest allowed), so every component is
// approximate.
//
// "-r other.txt" includes are followed through ctx.readFile, which only reads
// files inside the repo. Each file is read once, at most 5 levels deep.
const path = require('node:path');
const { ParseError } = require('../../common/errors');
const { skippedWarnings } = require('../../common/warnings');
const { byNameVersion, createManifestCollector } = require('../../common/components');
const { parsePep508 } = require('./pep508');
const { pypiLowest } = require('./versions');

const MAX_INCLUDE_DEPTH = 5;

// Joins "\" continuations, drops comments and blank lines.
function logicalLines(text) {
  return text
    .replace(/\\\r?\n/g, ' ')
    .split(/\r?\n/)
    .map((line) => line.replace(/(^|\s)#.*$/, '').trim())
    .filter(Boolean);
}

/**
 * @param {string} text  contents of the requirements file
 * @param {Object} ctx
 * @param {string} ctx.source  its path in the repo
 * @param {(relPath: string, format: 'text') => Promise<string>} ctx.readFile  safe reader for includes
 * @returns {Promise<{components: Object[], warnings: string[]}>}
 */
async function parseRequirementsTxt(text, { source, readFile }) {
  const c = createManifestCollector('PyPI');
  const extraWarnings = [];
  const visited = new Set([source]);

  async function processFile(rel, content, depth) {
    for (const line of logicalLines(content)) {
      const include = /^(?:-r|--requirement)[\s=]+(\S+)$/.exec(line);
      if (include) {
        await followInclude(path.posix.normalize(path.posix.join(path.posix.dirname(rel), include[1])), depth);
      } else if (line.startsWith('-')) {
        c.skipped.options.push(line.split(/\s+/)[0]);     // -e, -c, --index-url, ...
      } else if (/^[a-z][a-z0-9+.-]*:/i.test(line) || line.startsWith('.') || line.startsWith('/')) {
        c.skipped.nonRegistry.push(line);                 // URL, git+..., local path
      } else {
        // Per-requirement options like "--hash=sha256:..." come after the requirement.
        const req = parsePep508(line.split(/\s+--?[a-z]/i)[0]);
        if (!req) c.skipped.invalid.push(line);
        else if (req.url) c.skipped.nonRegistry.push(req.name);
        else c.add(req.name, pypiLowest(req.spec), false, rel);
      }
    }
  }

  async function followInclude(target, depth) {
    if (visited.has(target)) return;
    if (depth >= MAX_INCLUDE_DEPTH) {
      extraWarnings.push(`${source}: includes nested more than ${MAX_INCLUDE_DEPTH} levels were not followed`);
      return;
    }
    visited.add(target);
    let content;
    try {
      content = await readFile(target, 'text');
    } catch (err) {
      if (!(err instanceof ParseError)) throw err;
      extraWarnings.push(`${source}: included file not read (${err.message})`);
      return;
    }
    await processFile(target, content, depth + 1);
  }

  await processFile(source, text, 0);
  return {
    components: c.components.sort(byNameVersion),
    warnings: [...skippedWarnings(source, c.skipped), ...extraWarnings],
  };
}

module.exports = { parseRequirementsTxt };
