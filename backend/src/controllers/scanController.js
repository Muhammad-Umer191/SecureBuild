const ApiError = require('../utils/ApiError');
const scanQueries = require('../queries/scanQueries');
const { dispatchScanJob } = require('../worker');

/**
 * POST /api/scan/addRepo
 * Saves a GitHub repo for the user and spawns a background process to fetch & scan it.
 */
exports.addRepo = async (req, res, next) => {
  try {
    const normalizedUrl = req.body.url.replace(/\/+$/, '');
    const parts = new URL(normalizedUrl).pathname.replace(/^\/|\/$/g, '').split('/');
    const name = `${parts[0]}/${parts[1]}`;

    const existing = await scanQueries.findRepoByOwnerAndUrl(req.user._id, normalizedUrl);
    if (existing) {
      throw new ApiError(409, 'DUPLICATE', 'Repository already added');
    }

    const repo = await scanQueries.createRepo({
      owner: req.user._id,
      url: normalizedUrl,
      name,
      status: 'scanning',
    });

    const scan = await scanQueries.createScan({
      repo: repo._id,
      status: 'queued',
    });

    repo.lastScan = scan._id;
    await repo.save();

    dispatchScanJob({
      mode: 'scan',
      repoId: repo._id.toString(),
      scanId: scan._id.toString(),
      repoUrl: repo.url,
    });

    return res.status(201).json({ repo, scan });
  } catch (err) {
    return next(err);
  }
};

/**
 * GET /api/scan/fetchRepos
 * Gets all repositories from the DB for the authenticated user.
 */
exports.fetchRepos = async (req, res, next) => {
  try {
    const repos = await scanQueries.findReposByOwner(req.user._id);
    return res.json({ items: repos });
  } catch (err) {
    return next(err);
  }
};

/**
 * POST /api/scan/refreshRepo/:repoId
 * Spawns a background process to fetch new commits from the remote repo and update the local DB.
 */
exports.refreshRepo = async (req, res, next) => {
  try {
    if (req.repo.status === 'scanning') {
      throw new ApiError(409, 'SCAN_IN_PROGRESS', 'A scan is already running for this repository');
    }

    const latestScan = await scanQueries.findLatestCompletedScan(req.repo._id);
    const lastCommitSha = latestScan ? latestScan.commitSha : null;

    const scan = await scanQueries.createScan({
      repo: req.repo._id,
      status: 'queued',
    });

    req.repo.status = 'scanning';
    req.repo.lastScan = scan._id;
    await req.repo.save();

    dispatchScanJob({
      mode: 'refresh',
      repoId: req.repo._id.toString(),
      scanId: scan._id.toString(),
      repoUrl: req.repo.url,
      lastCommitSha,
    });

    return res.status(202).json({
      message: 'Repository refresh started in background',
      repo: req.repo,
      scan,
    });
  } catch (err) {
    return next(err);
  }
};
