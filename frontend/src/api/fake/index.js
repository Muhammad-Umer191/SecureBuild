// Fake API implementations returning the exact contract shapes (see docs/API_CONTRACT_F2.md).
import { ApiError } from '../client.js';
import { SCAN, buildFindings, buildBaseComponents } from './data.js';

const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, none: 1, unknown: 0 };
const LATENCY = 250;

let findings = buildFindings();
const baseComponents = buildBaseComponents();

const wait = (v) => new Promise((r) => setTimeout(() => r(v), LATENCY));
const failLater = (status, code, message) =>
  new Promise((_, rej) => setTimeout(() => rej(new ApiError(message, { code, status })), LATENCY));
const clone = (o) => JSON.parse(JSON.stringify(o));
const list = (v) => (v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : null);
const has = (v) => v !== undefined && v !== null && v !== '';

function summaryOf(f) {
  const { id, vulnId, cveIds, summary, package: pkg, direct, severity, score, hasFix, recommendedFix, status, published } = f;
  return clone({ id, vulnId, cveIds, summary, package: pkg, direct, severity, score, hasFix, recommendedFix, status, published });
}

export async function listFindings(_repoId, params = {}) {
  const status = params.status || 'open';
  const sevs = list(params.severity);
  const ecos = list(params.ecosystem);
  const q = (params.q || '').toLowerCase();
  const sort = params.sort || 'severity';
  const dir = (params.order || 'desc') === 'asc' ? 1 : -1;

  const base = findings.filter((f) => {
    if (status !== 'all' && f.status !== status) return false;
    if (ecos && !ecos.includes(f.package.ecosystem)) return false;
    if (has(params.hasFix) && String(f.hasFix) !== String(params.hasFix)) return false;
    if (has(params.direct) && String(f.direct) !== String(params.direct)) return false;
    if (q && !(f.package.name.toLowerCase().includes(q) || f.vulnId.toLowerCase().includes(q) || f.cveIds.some((c) => c.toLowerCase().includes(q)))) return false;
    return true;
  });
  const counts = { critical: 0, high: 0, medium: 0, low: 0, none: 0, unknown: 0 };
  base.forEach((f) => { counts[f.severity] += 1; });

  const filtered = sevs ? base.filter((f) => sevs.includes(f.severity)) : base;
  const cmp = {
    severity: (a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || (a.score ?? -1) - (b.score ?? -1),
    score: (a, b) => (a.score ?? -1) - (b.score ?? -1),
    package: (a, b) => a.package.name.localeCompare(b.package.name),
    published: (a, b) => a.published.localeCompare(b.published),
  }[sort] || (() => 0);
  const sorted = [...filtered].sort((a, b) => dir * cmp(a, b));

  const page = Math.max(1, parseInt(params.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(params.limit, 10) || 25));
  return wait({
    scan: { ...SCAN },
    items: sorted.slice((page - 1) * limit, page * limit).map(summaryOf),
    page, limit, total: sorted.length, counts,
  });
}

export async function getFinding(findingId) {
  const f = findings.find((x) => x.id === findingId);
  if (!f) return failLater(404, 'NOT_FOUND', 'Finding not found');
  return wait(clone(f));
}

export async function updateFinding(findingId, body = {}) {
  const f = findings.find((x) => x.id === findingId);
  if (!f) return failLater(404, 'NOT_FOUND', 'Finding not found');
  if (body.status === 'ignored') {
    const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
    if (reason.length < 5 || reason.length > 500) {
      return failLater(400, 'VALIDATION_ERROR', 'reason must be 5-500 characters when ignoring');
    }
    f.status = 'ignored';
    f.ignore = { reason, by: '665000000000000000000a01', at: new Date().toISOString() };
  } else if (body.status === 'open') {
    f.status = 'open';
    f.ignore = null;
  } else {
    return failLater(400, 'VALIDATION_ERROR', "status must be 'open' or 'ignored'");
  }
  return wait(clone(f));
}

function currentComponents() {
  return baseComponents.map((c) => {
    const open = findings.filter((f) => f.status === 'open' && f.package.purl === c.purl);
    let max = null;
    open.forEach((f) => { if (max === null || SEV_RANK[f.severity] > SEV_RANK[max]) max = f.severity; });
    return { ...c, licenses: [...c.licenses], vulnerabilityCount: open.length, maxSeverity: max };
  });
}

export async function listComponents(_repoId, params = {}) {
  const all = currentComponents();
  const ecos = list(params.ecosystem);
  const q = (params.q || '').toLowerCase();
  const sort = params.sort || 'name';
  const dir = (params.order || 'asc') === 'desc' ? -1 : 1;

  const filtered = all.filter((c) => {
    if (ecos && !ecos.includes(c.ecosystem)) return false;
    if (has(params.direct) && String(c.direct) !== String(params.direct)) return false;
    if (has(params.vulnerable) && String(c.vulnerabilityCount > 0) !== String(params.vulnerable)) return false;
    if (q && !(c.name.toLowerCase().includes(q) || c.purl.toLowerCase().includes(q))) return false;
    return true;
  });
  const cmp = {
    name: (a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()),
    vulns: (a, b) => a.vulnerabilityCount - b.vulnerabilityCount || a.name.localeCompare(b.name),
    ecosystem: (a, b) => a.ecosystem.localeCompare(b.ecosystem) || a.name.localeCompare(b.name),
  }[sort] || (() => 0);
  const sorted = [...filtered].sort((a, b) => dir * cmp(a, b));

  const page = Math.max(1, parseInt(params.page, 10) || 1);
  const limit = Math.min(200, Math.max(1, parseInt(params.limit, 10) || 50));
  const byEcosystem = {};
  all.forEach((c) => { byEcosystem[c.ecosystem] = (byEcosystem[c.ecosystem] || 0) + 1; });
  const direct = all.filter((c) => c.direct).length;
  return wait({
    scan: { ...SCAN },
    items: sorted.slice((page - 1) * limit, page * limit),
    page, limit, total: sorted.length,
    summary: {
      total: all.length, direct, transitive: all.length - direct,
      vulnerable: all.filter((c) => c.vulnerabilityCount > 0).length, byEcosystem,
    },
  });
}

/** Small valid CycloneDX 1.5 document built from the fake components. */
export async function exportSbom() {
  const comps = currentComponents();
  const doc = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
    version: 1,
    metadata: {
      timestamp: SCAN.finishedAt,
      component: { type: 'application', name: 'demo-repo', 'bom-ref': 'demo-repo' },
    },
    components: comps.map((c) => ({
      type: 'library', 'bom-ref': c.purl, name: c.name, version: c.version, purl: c.purl,
      licenses: c.licenses.map((id) => ({ license: { id } })),
    })),
    vulnerabilities: findings.filter((f) => f.status === 'open').map((f) => ({
      id: f.vulnId,
      source: { name: 'OSV', url: `https://osv.dev/vulnerability/${f.vulnId}` },
      description: f.summary,
      ratings: f.score === null ? [] : [{ score: f.score, severity: f.severity, vector: f.cvssVector }],
      affects: [{ ref: f.package.purl }],
    })),
  };
  const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/vnd.cyclonedx+json' });
  return wait({ blob, filename: 'demo-repo-sbom.cdx.json' });
}
