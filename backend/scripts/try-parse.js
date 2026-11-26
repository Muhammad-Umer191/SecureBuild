#!/usr/bin/env node
// Manual check of the parsers: clone -> discover -> parse, then print the
// resulting SBOM (one entry per package version, with its purl).
//
//   npm run try:parse -- https://github.com/OWASP/NodeGoat
//   npm run try:parse -- https://github.com/OWASP/NodeGoat --show 30 --json sbom.json
const fs = require('node:fs');
const { withClone } = require('../src/services/clone');
const { discoverDependencyFiles } = require('../src/services/discovery');
const { parseSources } = require('../src/services/parsers');

function flag(flags, name, fallback) {
  const i = flags.indexOf(name);
  return i === -1 ? fallback : flags[i + 1];
}

async function main() {
  const [url, ...flags] = process.argv.slice(2);
  if (!url) {
    console.error('Usage: npm run try:parse -- <github-url> [--show N] [--json out.json]');
    process.exit(2);
  }
  const show = Number(flag(flags, '--show', 15));
  const jsonOut = flag(flags, '--json', null);

  await withClone(url, async ({ dir, commitSha }) => {
    const discovery = await discoverDependencyFiles(dir);
    const { components, warnings, stats } = await parseSources(dir, discovery.sources);
    const count = (fn) => components.filter(fn).length;

    console.log(`Commit:   ${commitSha}`);
    console.log(`Sources:  ${discovery.sources.map((s) => `${s.path} (${s.kind})`).join(', ') || '(none)'}`);
    console.log(`Packages: ${stats.unique} unique (${stats.raw} entries read, ${stats.duplicatesMerged} duplicates merged)`);
    console.log(`  npm ${count((c) => c.ecosystem === 'npm')}, PyPI ${count((c) => c.ecosystem === 'PyPI')}`);
    console.log(`  direct ${count((c) => c.direct)}, dev ${count((c) => c.dev)}, approximate ${count((c) => c.approximate)}, with license ${count((c) => c.license)}`);

    const sorted = [...components].sort((a, b) => Number(b.direct) - Number(a.direct));
    console.log(`\nFirst ${Math.min(show, sorted.length)} (direct first):`);
    sorted.slice(0, show).forEach((c) => {
      const tags = [c.direct ? 'direct' : 'transitive', c.dev && 'dev', c.approximate && 'approx'].filter(Boolean).join(', ');
      const deps = c.dependsOn.length ? `  -> ${c.dependsOn.slice(0, 3).join(', ')}${c.dependsOn.length > 3 ? ', ...' : ''}` : '';
      console.log(`  ${c.purl.padEnd(44)} ${tags.padEnd(20)}${deps}`);
    });

    const allWarnings = [...discovery.warnings, ...warnings];
    console.log(`\nWarnings (${allWarnings.length}):`);
    if (!allWarnings.length) console.log('  (none)');
    allWarnings.forEach((w) => console.log(`  - ${w}`));

    if (jsonOut) {
      fs.writeFileSync(jsonOut, JSON.stringify(components, null, 2));
      console.log(`\nFull SBOM written to ${jsonOut}`);
    }
  });
}

main().catch((err) => {
  console.error(`\nFailed: [${err.code || err.name}] ${err.message}`);
  process.exit(1);
});
