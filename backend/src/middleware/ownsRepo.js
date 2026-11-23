// Middleware that loads a repo by :repoId, confirms the logged-in user owns it,
// and attaches it to req.repo.
const { Repo } = require('../models');
const ApiError = require('../utils/ApiError');

async function ownsRepo(req, _res, next) {
  try {
    const repo = await Repo.findById(req.params.repoId);
    if (!repo) {
      throw new ApiError(404, 'NOT_FOUND', 'Repository not found');
    }
    if (repo.owner.toString() !== req.user._id.toString()) {
      throw new ApiError(404, 'NOT_FOUND', 'Repository not found');
    }
    req.repo = repo;
    return next();
  } catch (err) {
    if (err.name === 'CastError') {
      return next(new ApiError(400, 'VALIDATION_ERROR', 'Invalid repository ID'));
    }
    return next(err);
  }
}

module.exports = ownsRepo;
