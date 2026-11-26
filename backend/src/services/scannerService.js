// Stub scanning service – to be implemented by the Scanner Engineer (B2).
// Provides the interface expected by scan.controller.js and worker/index.js.
const logger = require('../utils/logger');

/**
 * Fetches & scans a GitHub repository from the web.
 * @param {string} repoUrl  e.g. "https://github.com/owner/repo"
 * @returns {Promise<{ commitSha: string|null, findings: object[], components: object[] }>}
 */
async function scanRepository(repoUrl) {
  logger.info('[scanner.service] scanRepository called for %s (stub)', repoUrl);
  return {
    commitSha: null,
    findings: [],
    components: [],
  };
}

/**
 * Checks a remote GitHub repository for new commits since `lastCommitSha`
 * and returns scan results if new commits exist.
 * @param {string} repoUrl
 * @param {string|null} lastCommitSha
 * @returns {Promise<{ hasNewCommits: boolean, commitSha: string|null, findings: object[], components: object[] }>}
 */
async function refreshRepository(repoUrl, lastCommitSha = null) {
  logger.info(
    '[scanner.service] refreshRepository called for %s (lastCommitSha=%s) (stub)',
    repoUrl,
    lastCommitSha,
  );
  return {
    hasNewCommits: false,
    commitSha: lastCommitSha,
    findings: [],
    components: [],
  };
}

module.exports = {
  scanRepository,
  refreshRepository,
};
