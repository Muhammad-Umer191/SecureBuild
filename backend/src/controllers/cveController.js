const ApiError = require('../utils/ApiError');
const { getCveLookup } = require('../services/cve');

/**
 * GET /api/cve/:cveId
 * Fallback lookup: score, severity and description of one CVE from cvelistV5 (cached).
 */
exports.getCve = async (req, res, next) => {
  try {
    const lookup = req.app.locals.cveLookup || getCveLookup();
    const info = await lookup.lookup(req.params.cveId);
    if (!info) throw new ApiError(404, 'NOT_FOUND', 'CVE not found');
    res.set('Cache-Control', 'private, max-age=3600');
    return res.json(info);
  } catch (err) {
    return next(err);
  }
};
