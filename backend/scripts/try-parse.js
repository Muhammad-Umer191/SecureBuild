#!/usr/bin/env node
// Manual check of the parsers: clone -> discover -> parse, then print what
// was found.
//
//   npm run try:parse -- https://github.com/python-poetry/poetry
//   npm run try:parse -- https://github.com/OWASP/NodeGoat --show 30
const { withClone } = require('../src/services/clone');
const { discoverDependencyFiles } = require('../src/services/discovery');
const { parseSources } = require('../src/services/parsers');

async function main() {
  const [url, ...flags] = process.argv.slice(2);
  if (!url) {
    console.error('Usage: npm run try:parse -- <github-url> [--show N]');
    process.exit(2);
  }
  const showIdx = flags.indexOf('--show');
  const show = showIdx === -1 ? 15 : Number(flags[showIdx + 1]);

  await withClone(url, async ({ dir, commitSha }) => {
    const discovery = await discoverDependencyFiles(dir);
    const { components, warnings } = await parseSources(dir, discovery.sources);
    const count = (fn) => components.filter(fn).length;

    console.log(`Commit:      ${commitSha}`);
    console.log(`Sources:     ${discovery.sources.map((s) => `${s.path} (${s.kind})`).join(', ') || '(none)'}`);
    console.log(`Components:  ${components.length}  (npm ${count((c) => c.ecosystem === 'npm')}, PyPI ${count((c) => c.ecosystem === 'PyPI')})`);
    console.log(`  direct:    ${count((c) => c.direct)}   transitive: ${count((c) => !c.direct)}`);
    console.log(`  dev:       ${count((c) => c.dev)}   approximate: ${count((c) => c.approximate)}`);
    console.log(`  with license: ${count((c) => c.license)}   dependency links: ${components.reduce((n, c) => n + c.dependsOn.length, 0)}`);

    // Direct dependencies first, then the rest.
    const sorted = [...components].sort((a, b) => Number(b.direct) - Number(a.direct) || a.name.localeCompare(b.name));
    console.log(`\nFirst ${Math.min(show, sorted.length)} components:`);
    sorted.slice(0, show).forEach((c) => {
      const flags2 = [c.direct ? 'direct' : 'transitive', c.dev && 'dev', c.approximate && 'approx'].filter(Boolean).join(', ');
      const needs = c.dependsOn.length ? `  -> ${c.dependsOn.map((d) => `${d.name}@${d.version}`).slice(0, 4).join(', ')}${c.dependsOn.length > 4 ? ', ...' : ''}` : '';
      console.log(`  ${`${c.name}@${c.version}`.padEnd(38)} ${flags2.padEnd(22)}${needs}`);
    });

    const allWarnings = [...discovery.warnings, ...warnings];
    console.log(`\nWarnings (${allWarnings.length}):`);
    if (!allWarnings.length) console.log('  (none)');
    allWarnings.forEach((w) => console.log(`  - ${w}`));
  });
}

main().catch((err) => {
  console.error(`\nFailed: [${err.code || err.name}] ${err.message}`);
  process.exit(1);
});
