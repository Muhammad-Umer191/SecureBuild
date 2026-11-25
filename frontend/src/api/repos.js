import { request, USE_FAKE_API } from './client.js';

const fake = () => import('./fake/portal.js');

// Matches the backend validation rule in backend/src/models/Repo.js.
export const GITHUB_REPO_URL_RE = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)\/?$/;

/**
 * Validate and normalize a GitHub repository URL before sending it to the server.
 * Returns { valid, normalizedUrl, name, error }.
 */
export function validateRepoUrl(rawUrl) {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed) {
    return { valid: false, normalizedUrl: '', name: '', error: 'Please enter a GitHub repository URL.' };
  }

  const match = GITHUB_REPO_URL_RE.exec(trimmed);
  if (!match) {
    return {
      valid: false,
      normalizedUrl: trimmed,
      name: '',
      error: 'Use a valid GitHub URL like https://github.com/owner/repo.',
    };
  }

  const owner = match[1];
  const repo = match[2];
  return {
    valid: true,
    normalizedUrl: `https://github.com/${owner}/${repo}`,
    name: `${owner}/${repo}`,
    error: null,
  };
}

/** GET /repos -> { items: [...] } */
export async function listRepos() {
  if (USE_FAKE_API) return (await fake()).listRepos();
  const data = await request('/repos');
  return Array.isArray(data) ? { items: data } : data;
}

/** POST /repos -> { repo } */
export async function addRepo({ url }) {
  if (USE_FAKE_API) return (await fake()).addRepo({ url });
  return request('/repos', { method: 'POST', body: { url: String(url || '').trim() } });
}

/** DELETE /repos/:repoId */
export async function deleteRepo(repoId) {
  if (USE_FAKE_API) return (await fake()).deleteRepo(repoId);
  return request(`/repos/${encodeURIComponent(repoId)}`, { method: 'DELETE' });
}

/** POST /repos/:repoId/scans -> triggers a fresh scan for this repository */
export async function triggerScan(repoId) {
  if (USE_FAKE_API) return (await fake()).triggerScan(repoId);
  return request(`/repos/${encodeURIComponent(repoId)}/scans`, { method: 'POST' });
}
