const ApiError = require('../utils/ApiError');
const logger = require('../utils/logger');
const componentQueries = require('../queries/componentQueries');
const { buildSbom, sbomFileName } = require('../services/sbomExport');

/**
 * GET /api/component/show/:repoId
 * Components (SBOM) of a repo with filters, sorting, paging and summary totals.
 */
exports.listComponents = async (req, res, next) => {
  try {
    const result = await componentQueries.listComponents(req.repo._id, req.query);
    return res.json(result);
  } catch (err) {
    return next(err);
  }
};

/**
 * GET /api/component/export/:repoId?format=cyclonedx
 * Downloads the repo's SBOM as a CycloneDX 1.5 JSON file.
 */
exports.exportSbom = async (req, res, next) => {
  try {
    const { components, findings, latestScan } = await componentQueries.loadSbomData(req.repo._id);
    if (!latestScan && !components.length) {
      throw new ApiError(404, 'NO_SCAN', 'This repository has not been scanned yet');
    }
    const bom = buildSbom({ repo: req.repo, scan: latestScan, components, findings });

    logger.info('[audit] sbom.export user=%s repo=%s components=%d vulnerabilities=%d',
      req.user._id, req.repo._id, bom.components.length, bom.vulnerabilities.length);

    res.set('Content-Type', 'application/vnd.cyclonedx+json; charset=utf-8');
    res.set('Content-Disposition', `attachment; filename="${sbomFileName(req.repo)}"`);
    res.set('Cache-Control', 'no-store');
    return res.send(JSON.stringify(bom, null, 2));
  } catch (err) {
    return next(err);
  }
};
