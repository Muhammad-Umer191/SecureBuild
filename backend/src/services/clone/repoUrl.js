// Validates GitHub repo URLs. Anything else is rejected before git ever runs.

// owner: letters, digits and hyphens, not starting with a hyphen (max 39).
// repo:  letters, digits, ".", "_", "-" (max 100). Optional ".git" and "/".
const GITHUB_URL = /^https:\/\/github\.com\/([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?\/?$/;

/**
 * @param {string} url
 * @returns {{owner: string, repo: string, cloneUrl: string}|null} null if not a valid GitHub repo URL
 */
function parseRepoUrl(url) {
  if (typeof url !== 'string') return null;
  const m = GITHUB_URL.exec(url.trim());
  if (!m) return null;
  const [, owner, repo] = m;
  if (repo === '.' || repo === '..') return null;
  return { owner, repo, cloneUrl: `https://github.com/${owner}/${repo}.git` };
}

/** @returns {boolean} true only for https://github.com/<owner>/<repo>[.git][/] */
function isValidRepoUrl(url) {
  return parseRepoUrl(url) !== null;
}

module.exports = { parseRepoUrl, isValidRepoUrl };
