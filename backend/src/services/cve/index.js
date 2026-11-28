// CVE module (F2): fallback lookup CVE id -> score from cvelistV5.
//
//   lookup(id)              -> parsed CVE info (cached in MongoDB) or null
//   enrichFinding(finding)  -> fills finding.cves, and the score if OSV had none
//
// The worker can call enrichFinding() right after saving a scan's findings so
// scores are filled at scan time; the finding-detail endpoint also calls it
// (cheap when already done), so nothing is missed if the worker doesn't.
// Import from here (require('./services/cve')).
const { createCveLookup, memoryCache, mongoCache } = require('./cveLookup');
const { enrichFinding } = require('./enrichFinding');
const cveRecord = require('./cveRecord');

let defaultLookup = null;
function getCveLookup() {
  if (!defaultLookup) defaultLookup = createCveLookup();
  return defaultLookup;
}

module.exports = {
  createCveLookup,
  getCveLookup,
  memoryCache,
  mongoCache,
  enrichFinding: (finding, lookup = getCveLookup()) => enrichFinding(finding, lookup),
  ...cveRecord,
};
