// componentQueries.js – DB reads for the SBOM tab (components of a repo).
const { Component, Finding, Scan } = require('../models');

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function buildComponentFilter(repoId, params = {}) {
  const filter = { repo: repoId };
  if (params.ecosystem) filter.ecosystem = { $in: params.ecosystem.split(',') };
  if (params.direct) filter.direct = params.direct === 'true';
  if (params.vulnerable) filter.vulnerabilityCount = params.vulnerable === 'true' ? { $gt: 0 } : 0;
  if (params.q) {
    const rx = new RegExp(escapeRegex(params.q), 'i');
    filter.$or = [{ name: rx }, { purl: rx }];
  }
  return filter;
}

function sortOption(sort = 'name', order = 'asc') {
  const dir = order === 'desc' ? -1 : 1;
  if (sort === 'vulns') return { vulnerabilityCount: dir, name: 1, _id: 1 };
  if (sort === 'ecosystem') return { ecosystem: dir, name: 1, _id: 1 };
  return { name: dir, version: dir, _id: 1 };
}

/** Whole-repo totals for the summary cards (ignores filters). */
async function componentSummary(repoId) {
  const [row] = await Component.aggregate([
    { $match: { repo: repoId } },
    {
      $facet: {
        totals: [{
          $group: {
            _id: null,
            total: { $sum: 1 },
            direct: { $sum: { $cond: ['$direct', 1, 0] } },
            vulnerable: { $sum: { $cond: [{ $gt: ['$vulnerabilityCount', 0] }, 1, 0] } },
          },
        }],
        byEcosystem: [{ $group: { _id: '$ecosystem', n: { $sum: 1 } } }],
      },
    },
  ]);
  const t = (row && row.totals[0]) || { total: 0, direct: 0, vulnerable: 0 };
  return {
    total: t.total,
    direct: t.direct,
    transitive: t.total - t.direct,
    vulnerable: t.vulnerable,
    byEcosystem: Object.fromEntries(((row && row.byEcosystem) || []).map((e) => [e._id, e.n])),
  };
}

const toComponent = (c) => ({
  id: c._id,
  name: c.name,
  version: c.version,
  ecosystem: c.ecosystem,
  purl: c.purl,
  direct: Boolean(c.direct),
  licenses: c.licenses || [],
  vulnerabilityCount: c.vulnerabilityCount || 0,
  maxSeverity: c.maxSeverity || null,
});

async function listComponents(repoId, params = {}) {
  const { sort, order, page = 1, limit = 50 } = params;
  const filter = buildComponentFilter(repoId, params);
  const [items, total, summary, latestScan] = await Promise.all([
    Component.find(filter).sort(sortOption(sort, order)).skip((page - 1) * limit).limit(limit).lean(),
    Component.countDocuments(filter),
    componentSummary(repoId),
    Scan.findOne({ repo: repoId, status: 'completed' }).sort({ finishedAt: -1 }).lean(),
  ]);
  return {
    scan: latestScan
      ? { id: latestScan._id, finishedAt: latestScan.finishedAt, commitSha: latestScan.commitSha }
      : null,
    items: items.map(toComponent),
    page,
    limit,
    total,
    summary,
  };
}

/** Everything the SBOM export needs, read in one go. */
async function loadSbomData(repoId) {
  const [components, findings, latestScan] = await Promise.all([
    Component.find({ repo: repoId }).sort({ purl: 1 }).lean(),
    Finding.find({ repo: repoId, status: 'open' }).lean(),
    Scan.findOne({ repo: repoId, status: 'completed' }).sort({ finishedAt: -1 }).lean(),
  ]);
  return { components, findings, latestScan };
}

module.exports = { listComponents, componentSummary, loadSbomData, buildComponentFilter };
