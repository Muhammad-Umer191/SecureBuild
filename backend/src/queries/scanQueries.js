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

async function upsertFindingsForScan(repoId, scanId, findings = []) {
  let savedCount = 0;
  for (const f of findings) {
    await Finding.findOneAndUpdate(
      { repo: repoId, vulnId: f.vulnId },
      {
        $set: {
          scan: scanId,
          vulnId: f.vulnId,
          aliases: f.aliases || [],
          cveIds: f.cveIds || [],
          summary: f.summary,
          details: f.details || '',
          package: f.package,
          direct: f.direct ?? false,
          cvssVector: f.cvssVector ?? null,
          score: f.score ?? null,
          severity: f.severity || 'unknown',
          scoreSource: f.scoreSource ?? null,
          hasFix: (f.fixedVersions || []).length > 0,
          fixedVersions: f.fixedVersions || [],
          recommendedFix: f.recommendedFix ?? null,
          dependencyPath: f.dependencyPath || [],
          references: f.references || [],
          cwes: f.cwes || [],
          cves: f.cves || [],
          scoring: f.scoring,
          published: f.published ? new Date(f.published) : null,
          modified: f.modified ? new Date(f.modified) : null,
        },
        $setOnInsert: {
          repo: repoId,
          status: 'open',
          ignore: null,
          firstSeenAt: new Date(),
        },
      },
      { upsert: true, new: true },
    );
    savedCount += 1;
  }
  return savedCount;
}

async function replaceComponentsForScan(repoId, scanId, components = []) {
  await Component.deleteMany({ repo: repoId });
  if (components.length === 0) return 0;

  const docs = components.map((c) => ({
    repo: repoId,
    scan: scanId,
    name: c.name,
    version: c.version,
    ecosystem: c.ecosystem,
    purl: c.purl,
    direct: c.direct ?? false,
    licenses: c.licenses || [],
    vulnerabilityCount: c.vulnerabilityCount || 0,
    maxSeverity: c.maxSeverity || null,
  }));

  await Component.insertMany(docs, { ordered: false });
  return docs.length;
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
