// Standalone background worker process spawned via child_process.fork().
// Runs repository fetching/scanning without blocking the main API event loop.
const mongoose = require('mongoose');
const connectDB = require('../config/db');
const { Repo, Scan } = require('../models');
const scanQueries = require('../queries/scanQueries');
const scannerService = require('../services/scannerService');
const logger = require('../utils/logger');

async function runJob(job) {
  const { mode, repoId, scanId, repoUrl, lastCommitSha } = job;
  await connectDB();

  const scan = await Scan.findById(scanId);
  const repo = await Repo.findById(repoId);
  if (!scan || !repo) {
    logger.warn('Background worker: missing repo (%s) or scan (%s)', repoId, scanId);
    await mongoose.disconnect();
    return;
  }

  scan.status = 'running';
  scan.startedAt = new Date();
  await scan.save();

  try {
    let findingsCount = 0;
    let componentsCount = 0;
    let commitSha = lastCommitSha || null;

    if (mode === 'refresh') {
      const results = await scannerService.refreshRepository(repoUrl, lastCommitSha);
      commitSha = results.commitSha || lastCommitSha || null;
      if (results.hasNewCommits) {
        findingsCount = await scanQueries.upsertFindingsForScan(repo._id, scan._id, results.findings);
        componentsCount = await scanQueries.replaceComponentsForScan(repo._id, scan._id, results.components);
      }
    } else {
      const results = await scannerService.scanRepository(repoUrl);
      commitSha = results.commitSha || null;
      findingsCount = await scanQueries.upsertFindingsForScan(repo._id, scan._id, results.findings);
      componentsCount = await scanQueries.replaceComponentsForScan(repo._id, scan._id, results.components);
    }

    scan.status = 'completed';
    scan.commitSha = commitSha;
    scan.finishedAt = new Date();
    scan.findingsCount = findingsCount;
    scan.componentsCount = componentsCount;
    await scan.save();

    repo.lastScan = scan._id;
    repo.status = 'idle';
    await repo.save();

    logger.info('Background %s completed for %s', mode, repo.name);
  } catch (err) {
    logger.error('Background %s failed for %s: %s', mode, repo.name, err.message);
    scan.status = 'failed';
    scan.error = err.message;
    scan.finishedAt = new Date();
    await scan.save();

    repo.lastScan = scan._id;
    repo.status = 'error';
    await repo.save();
    throw err;
  } finally {
    await mongoose.disconnect();
  }
}

process.on('message', async (job) => {
  try {
    await runJob(job);
    process.exit(0);
  } catch (_err) {
    process.exit(1);
  }
});
