// scanWorker.js – spawned by worker/index.js via child_process.fork().
// Runs entirely in its own process so cloning / OSV queries never block the API server.
// Receives one message: { mode, repoId, scanId, repoUrl, lastCommitSha }
// then exits 0 (success) or 1 (failure).

process.on('message', async (job) => {
  // Lazy-require inside the handler so the module system is fully ready.
  const mongoose         = require('mongoose');
  const connectDB        = require('../config/db');
  const { Repo, Scan, Finding, Component } = require('../models');
  const scannerService   = require('../services/scannerService');
  const logger           = require('../utils/logger');

  const { mode, repoId, scanId, repoUrl, lastCommitSha } = job;
  const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, none: 1, unknown: 0 };

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
    let result;
    if (mode === 'refresh') {
      result = await scannerService.refreshRepository(repoUrl, lastCommitSha);
    } else {
      result = await scannerService.scanRepository(repoUrl);
    }

    const shouldUpdate = mode !== 'refresh' || result.hasNewCommits;
    let findingsCount = 0;
    let componentsCount = 0;

    if (shouldUpdate) {
      // ── save findings (upsert by vulnId so "ignore" status is never reset) ─
      const activeVulnIds = [];
      for (const f of result.findings) {
        activeVulnIds.push(f.vulnId);
        await Finding.findOneAndUpdate(
          { repo: repo._id, vulnId: f.vulnId },
          {
            $set: {
              scan: scan._id,
              ...f,
              repo: repo._id,
            },
            $setOnInsert: {
              status:      'open',
              ignore:      null,
              firstSeenAt: new Date(),
            },
          },
          { upsert: true, new: true },
        );
        findingsCount += 1;
      }

      // Remove findings that no longer exist in the latest scan
      await Finding.deleteMany({
        repo: repo._id,
        vulnId: { $nin: activeVulnIds },
      });

      // ── save components (always replace; SBOM is the latest snapshot) ──────
      await Component.deleteMany({ repo: repo._id });
      if (result.components.length > 0) {
        const docs = result.components.map((c) => ({ ...c, repo: repo._id, scan: scan._id }));
        await Component.insertMany(docs, { ordered: false });
        componentsCount = docs.length;
      }

      // ── recompute vulnerability counts on each component ──────────────────
      if (findingsCount > 0 && componentsCount > 0) {
        const openFindings = await Finding.find({ repo: repo._id, status: 'open' });
        const purlVulns   = {};
        const purlMaxSev  = {};
        for (const of_ of openFindings) {
          const p = of_.package.purl;
          purlVulns[p]  = (purlVulns[p] || 0) + 1;
          const rank    = SEV_RANK[of_.severity] ?? 0;
          if (!purlMaxSev[p] || rank > SEV_RANK[purlMaxSev[p]]) purlMaxSev[p] = of_.severity;
        }
        for (const [purl, cnt] of Object.entries(purlVulns)) {
          await Component.updateOne(
            { repo: repo._id, purl },
            { $set: { vulnerabilityCount: cnt, maxSeverity: purlMaxSev[purl] || null } },
          );
        }
      }
    } else {
      [findingsCount, componentsCount] = await Promise.all([
        Finding.countDocuments({ repo: repo._id }),
        Component.countDocuments({ repo: repo._id }),
      ]);
    }

    // ── finalise scan record ─────────────────────────────────────────────────
    scan.status           = 'completed';
    scan.commitSha        = result.commitSha || (mode === 'refresh' ? lastCommitSha : null);
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
