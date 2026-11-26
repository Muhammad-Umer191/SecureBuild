#!/usr/bin/env node
// Runs a full scan and prints what a user would see.
//
//   npm run scan -- https://github.com/OWASP/NodeGoat
//   npm run scan -- https://github.com/OWASP/NodeGoat --show 30 --json result.json
//   npm run scan -- https://github.com/OWASP/NodeGoat --cyclonedx nodegoat.cdx.json
const fs = require('node:fs');
const { scan } = require('../src/services/scan');
const { toCycloneDX } = require('../src/services/cyclonedx');

function flag(flags, name, fallback) {
  const i = flags.indexOf(name);
  return i === -1 ? fallback : flags[i + 1];
}

const pad = (s, n) => String(s).padEnd(n);

async function main() {
  const [url, ...flags] = process.argv.slice(2);
  if (!url) {
    console.error('Usage: npm run scan -- <github-url> [--show N] [--json out.json] [--cyclonedx out.cdx.json]');
    process.exit(2);
  }
  const show = Number(flag(flags, '--show', 15));
  const jsonOut = flag(flags, '--json', null);
  const cdxOut = flag(flags, '--cyclonedx', null);

  const result = await scan(url, { onProgress: (stage) => process.stderr.write(`  ... ${stage}\n`) });
  const { stats } = result;
  const d = stats.durationMs;

  console.log(`\nRepo:     ${result.repoUrl} @ ${result.commitSha}`);
  console.log(`Scanned:  ${result.scannedAt} in ${(d.total / 1000).toFixed(1)}s `
    + `(clone ${d.clone}ms, discover ${d.discover}ms, parse ${d.parse}ms, osv ${d.osv}ms, findings ${d.findings}ms)`);
  console.log(`Packages: ${stats.packages} scanned, ${stats.vulnerablePackages} vulnerable`);
  console.log(`Findings: ${stats.findings}, ${stats.fixable} fixable`);
  console.log(`  ${Object.entries(stats.bySeverity).map(([s, n]) => `${s} ${n}`).join(' | ')}`);

  console.log(`\nWorst ${Math.min(show, result.findings.length)} findings:`);
  if (!result.findings.length) console.log('  (none)');
  result.findings.slice(0, show).forEach((f) => {
    const score = f.score === null ? '  - ' : f.score.toFixed(1).padStart(4);
    const fix = f.fixedVersion ? `fix ${f.fixedVersion}` : 'no fix';
    console.log(`  ${pad(f.severity, 8)} ${score}  ${pad(f.purl, 36)} ${pad(f.cves[0] || f.vulnIds[0], 20)} ${pad(fix, 14)} `
      + `${f.approximate ? '(approx) ' : ''}${f.summary.slice(0, 50)}`);
  });

  console.log(`\nUpgrades (${result.upgrades.length} packages):`);
  result.upgrades.slice(0, show).forEach((u) => {
    const to = u.to ? `-> ${u.to}` : '-> (no fix)';
    const extra = u.unfixed ? `, ${u.unfixed} without a fix` : '';
    console.log(`  ${pad(u.worstSeverity, 8)} ${pad(`${u.name} ${u.from}`, 30)} ${pad(to, 16)} closes ${u.closes}${extra}`);
  });

  console.log(`\nWarnings (${result.warnings.length}):`);
  if (!result.warnings.length) console.log('  (none)');
  result.warnings.forEach((w) => console.log(`  - ${w}`));

  if (jsonOut) {
    fs.writeFileSync(jsonOut, JSON.stringify(result, null, 2));
    console.log(`\nFull ScanResult written to ${jsonOut}`);
  }
  if (cdxOut) {
    const bom = toCycloneDX(result);
    fs.writeFileSync(cdxOut, JSON.stringify(bom, null, 2));
    console.log(`CycloneDX 1.5 SBOM written to ${cdxOut} (${bom.components.length} components, ${bom.vulnerabilities.length} vulnerabilities)`);
  }
}

main().catch((err) => {
  const where = err.stage ? ` at ${err.stage}` : '';
  console.error(`\nScan failed${where}: [${err.code || err.name}] ${err.message}`);
  if (err.permanent !== undefined) console.error(`Permanent: ${err.permanent} (retrying ${err.permanent ? "won't" : 'might'} help)`);
  process.exit(1);
});
