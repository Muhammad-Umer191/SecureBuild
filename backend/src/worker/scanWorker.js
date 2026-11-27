// scanWorker.js – spawned by worker/index.js via child_process.fork().
// Runs entirely in its own process so cloning / OSV queries never block the API server.
// Receives one message: { mode, repoId, scanId, repoUrl }
// `mode` ('scan' | 'refresh') is only a label for the logs; both run the same full scan.
// then exits 0 (success) or 1 (failure).

process.on('message', async (job) => {
  // Lazy-require inside the handler so the module system is fully ready.
  const mongoose         = require('mongoose');
  const connectDB        = require('../config/db');
  const { Repo, Scan } = require('../models');
  const scannerService   = require('../services/scannerService');
  const scanQueries      = require('../queries/scanQueries');
  const { refreshComponentCounts } = require('../queries/componentQueries');
  const logger           = require('../utils/logger');

  const { mode, repoId, scanId, repoUrl } = job;

  try {
    await connectDB();

    const [repo, scan] = await Promise.all([
      Repo.findById(repoId),
      Scan.findById(scanId),
    ]);

    if (!repo || !scan) {
      logger.warn('[scanWorker] repo or scan not found (%s / %s)', repoId, scanId);
      await mongoose.disconnect();
      process.exit(0);
    }

    scan.status = 'running';
    scan.startedAt = new Date();
    await scan.save();

    // ── run the pipeline ─────────────────────────────────────────────────────
    // A refresh is a full scan too: new advisories appear on OSV even when the
    // code has not changed, so the results are always saved.
    const result = await scannerService.scanRepository(repoUrl);

    // ── save results ─────────────────────────────────────────────────────────
    // Findings: upsert by vulnId so an "ignored" status is never reset; stale ones removed.
    // Components: always replaced, since the SBOM is the latest snapshot.
    const findingsCount   = await scanQueries.replaceFindingsForScan(repo._id, scan._id, result.findings);
    const componentsCount = await scanQueries.replaceComponentsForScan(repo._id, scan._id, result.components);

    // Each component's open-finding count and worst severity (SBOM tab).
    if (findingsCount > 0 && componentsCount > 0) {
      await refreshComponentCounts(repo._id);
    }

    // ── finalise scan record ─────────────────────────────────────────────────
    scan.status           = 'completed';
    scan.commitSha        = result.commitSha || null;
    scan.finishedAt       = new Date();
    scan.findingsCount    = findingsCount;
    scan.componentsCount  = componentsCount;
    await scan.save();

    repo.lastScan = scan._id;
    repo.status   = 'idle';
    await repo.save();

    logger.info('[scanWorker] %s completed for %s — %d findings, %d components',
      mode, repo.name, findingsCount, componentsCount);

    await mongoose.disconnect();
    process.exit(0);
  } catch (err) {
    // Best-effort: mark the scan failed before exiting
    try {
      const mongoose2 = require('mongoose');
      const { Repo: R, Scan: S } = require('../models');
      const s = await S.findById(scanId);
      if (s) { s.status = 'failed'; s.error = err.message; s.finishedAt = new Date(); await s.save(); }
      const r = await R.findById(repoId);
      if (r) { r.status = 'error'; await r.save(); }
      await mongoose2.disconnect();
    } catch (_) { /* ignore cleanup errors */ }

    process.stderr.write(`[scanWorker] ${err.message}\n${err.stack}\n`);
    process.exit(1);
  }
});
