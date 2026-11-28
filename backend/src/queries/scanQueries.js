// scanQueries.js – all DB operations for the scan / repo layer.
const { Repo, Scan, Finding, Component } = require('../models');

async function createRepo({ owner, url, name, status = 'idle' }) {
  return Repo.create({ owner, url, name, status });
}

async function findRepoByOwnerAndUrl(owner, url) {
  return Repo.findOne({ owner, url });
}

async function findReposByOwner(owner) {
  return Repo.find({ owner })
    .sort({ createdAt: -1 })
    .populate('lastScan', 'status commitSha startedAt finishedAt findingsCount componentsCount');
}

async function createScan(data) {
  return Scan.create(data);
}

// Saves a scan's findings: upserts by vulnId (so an "ignored" status is never reset)
// and removes findings the latest scan no longer reports.
async function replaceFindingsForScan(repoId, scanId, findings = []) {
  for (const f of findings) {
    await Finding.findOneAndUpdate(
      { repo: repoId, vulnId: f.vulnId },
      {
        $set:        { scan: scanId, ...f, repo: repoId },
        $setOnInsert: { status: 'open', ignore: null, firstSeenAt: new Date() },
      },
      { upsert: true, new: true },
    );
  }
  await Finding.deleteMany({ repo: repoId, vulnId: { $nin: findings.map((f) => f.vulnId) } });
  return findings.length;
}

// Replaces the SBOM (always the latest full snapshot).
async function replaceComponentsForScan(repoId, scanId, components = []) {
  await Component.deleteMany({ repo: repoId });
  if (!components.length) return 0;
  await Component.insertMany(
    components.map((c) => ({ ...c, repo: repoId, scan: scanId })),
    { ordered: false },
  );
  return components.length;
}

module.exports = {
  createRepo,
  findRepoByOwnerAndUrl,
  findReposByOwner,
  createScan,
  replaceFindingsForScan,
  replaceComponentsForScan,
};
