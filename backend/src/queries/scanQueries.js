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

async function findLatestCompletedScan(repoId) {
  return Scan.findOne({ repo: repoId, status: 'completed' }).sort({ finishedAt: -1 });
}

// Upserts findings from a scan result; never resets existing ignore/status.
async function upsertFindingsForScan(repoId, scanId, findings = []) {
  let count = 0;
  for (const f of findings) {
    await Finding.findOneAndUpdate(
      { repo: repoId, vulnId: f.vulnId },
      {
        $set:        { scan: scanId, ...f, repo: repoId },
        $setOnInsert: { status: 'open', ignore: null, firstSeenAt: new Date() },
      },
      { upsert: true, new: true },
    );
    count += 1;
  }
  return count;
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
  findLatestCompletedScan,
  upsertFindingsForScan,
  replaceComponentsForScan,
};
