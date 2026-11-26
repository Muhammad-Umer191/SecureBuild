#!/usr/bin/env node
// Manual check of the OSV lookup: clone -> discover -> parse -> OSV.dev, then
// list the vulnerable packages and their advisories.
//
//   npm run try:osv -- https://github.com/OWASP/NodeGoat
//   npm run try:osv -- https://github.com/OWASP/NodeGoat --show 30 --twice   (2nd run shows the cache)
const { withClone } = require('../src/services/clone');
const { discoverDependencyFiles } = require('../src/services/discovery');
const { parseSources } = require('../src/services/parsers');
const { lookupVulnerabilities } = require('../src/services/osv');

function flag(flags, name, fallback) {
  const i = flags.indexOf(name);
  return i === -1 ? fallback : flags[i + 1];
}

const secondsSince = (t) => `${((Date.now() - t) / 1000).toFixed(1)}s`;

async function main() {
  const [url, ...flags] = process.argv.slice(2);
  if (!url) {
    console.error('Usage: npm run try:osv -- <github-url> [--show N] [--twice]');
    process.exit(2);
  }
  const show = Number(flag(flags, '--show', 15));

  // The clone is only needed until parsing is done.
  const { commitSha, components, parseWarnings } = await withClone(url, async ({ dir, commitSha: sha }) => {
    const discovery = await discoverDependencyFiles(dir);
    const parsed = await parseSources(dir, discovery.sources);
    return { commitSha: sha, components: parsed.components, parseWarnings: [...discovery.warnings, ...parsed.warnings] };
  });
  console.log(`Commit:   ${commitSha}`);
  console.log(`Packages: ${components.length} in the SBOM`);

  const runs = flags.includes('--twice') ? 2 : 1;
  let result;
  for (let run = 1; run <= runs; run += 1) {
    const started = Date.now();
    result = await lookupVulnerabilities(components);
    const s = result.stats;
    console.log(`OSV run ${run}: ${secondsSince(started)} | ${s.queried} queried, ${s.vulnerablePackages} vulnerable, `
      + `${s.advisories} advisories (${s.fetched} downloaded, ${s.fromCache} from cache, ${s.withdrawn} withdrawn)`);
  }

  const byPurl = new Map(components.map((c) => [c.purl, c]));
  const sorted = [...result.matches].sort((a, b) => b.records.length - a.records.length);
  console.log(`\nMost affected ${Math.min(show, sorted.length)} packages:`);
  if (!sorted.length) console.log('  (no known vulnerabilities)');
  sorted.slice(0, show).forEach((m) => {
    const c = byPurl.get(m.purl);
    const tags = [c.direct ? 'direct' : 'transitive', c.dev && 'dev', c.approximate && 'approx'].filter(Boolean).join(', ');
    const ids = m.records.map((r) => r.id);
    console.log(`  ${m.purl.padEnd(40)} ${String(ids.length).padStart(3)}  ${tags.padEnd(20)} ${ids.slice(0, 3).join(', ')}${ids.length > 3 ? ', ...' : ''}`);
  });

  const warnings = [...parseWarnings, ...result.warnings];
  console.log(`\nWarnings (${warnings.length}):`);
  if (!warnings.length) console.log('  (none)');
  warnings.forEach((w) => console.log(`  - ${w}`));
}

main().catch((err) => {
  console.error(`\nFailed: [${err.code || err.name}] ${err.message}`);
  process.exit(1);
});
