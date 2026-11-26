#!/usr/bin/env node
// Manual check of the findings: clone -> discover -> parse -> OSV -> findings,
// then print what a user would see: counts per severity, the worst findings,
// and the upgrades that fix them.
//
//   npm run try:findings -- https://github.com/OWASP/NodeGoat
//   npm run try:findings -- https://github.com/OWASP/NodeGoat --show 30 --json findings.json
const fs = require('node:fs');
const { withClone } = require('../src/services/clone');
const { discoverDependencyFiles } = require('../src/services/discovery');
const { parseSources } = require('../src/services/parsers');
const { lookupVulnerabilities } = require('../src/services/osv');
const { buildFindings } = require('../src/services/findings');

function flag(flags, name, fallback) {
  const i = flags.indexOf(name);
  return i === -1 ? fallback : flags[i + 1];
}

const pad = (s, n) => String(s).padEnd(n);

async function main() {
  const [url, ...flags] = process.argv.slice(2);
  if (!url) {
    console.error('Usage: npm run try:findings -- <github-url> [--show N] [--json out.json]');
    process.exit(2);
  }
  const show = Number(flag(flags, '--show', 15));
  const jsonOut = flag(flags, '--json', null);

  const { commitSha, components, earlyWarnings } = await withClone(url, async ({ dir, commitSha: sha }) => {
    const discovery = await discoverDependencyFiles(dir);
    const parsed = await parseSources(dir, discovery.sources);
    return { commitSha: sha, components: parsed.components, earlyWarnings: [...discovery.warnings, ...parsed.warnings] };
  });
  const osv = await lookupVulnerabilities(components);
  const { findings, upgrades, warnings, stats } = buildFindings(components, osv.matches);

  console.log(`Commit:   ${commitSha}`);
  console.log(`Packages: ${components.length} scanned, ${stats.packages} vulnerable`);
  console.log(`Findings: ${stats.findings} (${stats.advisoryRecords} advisory-package matches, ${stats.mergedAway} merged as aliases), ${stats.fixable} fixable`);
  console.log(`  ${Object.entries(stats.bySeverity).map(([s, n]) => `${s} ${n}`).join(' | ')}`);

  console.log(`\nWorst ${Math.min(show, findings.length)} findings:`);
  if (!findings.length) console.log('  (none)');
  findings.slice(0, show).forEach((f) => {
    const score = f.score === null ? '  - ' : f.score.toFixed(1).padStart(4);
    const fix = f.fixedVersion ? `fix ${f.fixedVersion}` : 'no fix';
    const id = f.cves[0] || f.vulnIds[0];
    console.log(`  ${pad(f.severity, 8)} ${score}  ${pad(f.purl, 36)} ${pad(id, 20)} ${pad(fix, 14)} ${f.approximate ? '(approx) ' : ''}${f.summary.slice(0, 50)}`);
  });

  console.log(`\nUpgrades (${upgrades.length} packages):`);
  upgrades.slice(0, show).forEach((u) => {
    const to = u.to ? `-> ${u.to}` : '-> (no fix)';
    const extra = u.unfixed ? `, ${u.unfixed} without a fix` : '';
    console.log(`  ${pad(u.worstSeverity, 8)} ${pad(`${u.name} ${u.from}`, 30)} ${pad(to, 16)} closes ${u.closes}${extra}`);
  });

  const all = [...earlyWarnings, ...osv.warnings, ...warnings];
  console.log(`\nWarnings (${all.length}):`);
  if (!all.length) console.log('  (none)');
  all.forEach((w) => console.log(`  - ${w}`));

  if (jsonOut) {
    fs.writeFileSync(jsonOut, JSON.stringify({ findings, upgrades }, null, 2));
    console.log(`\nFull findings written to ${jsonOut}`);
  }
}

main().catch((err) => {
  console.error(`\nFailed: [${err.code || err.name}] ${err.message}`);
  process.exit(1);
});
