import { ApiError, request, USE_FAKE_API } from './client.js';

const fake = () => import('./fake/portal.js');

// Matches the backend validation rule in backend/src/models/Repo.js and scanValidator.js.
export const GITHUB_REPO_URL_RE = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)\/?$/;

/** Normalize a backend Scan document (`_id` -> `id`). */
export function toScan(doc) {
  if (!doc || typeof doc !== 'object') return null;
  const { _id, __v, ...rest } = doc;
  return { ...rest, id: String(rest.id ?? _id) };
}

/** Normalize a backend Repo document (`_id` -> `id`, populated `lastScan`). */
export function toRepo(doc, fallbackScan = null) {
  if (!doc || typeof doc !== 'object') return doc;
  const { _id, __v, ...rest } = doc;
  const rawScan = typeof rest.lastScan === 'object' && rest.lastScan !== null ? rest.lastScan : fallbackScan;
  return {
    ...rest,
    id: String(rest.id ?? _id),
    lastScan: toScan(rawScan),
  };
}

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

/** GET /scan/fetchRepos -> { items: [...] } */
export async function listRepos() {
  if (USE_FAKE_API) return (await fake()).listRepos();
  const data = await request('/scan/fetchRepos');
  const rawItems = Array.isArray(data) ? data : data?.items || [];
  return { items: rawItems.map((r) => toRepo(r)) };
}

/** POST /scan/addRepo -> normalized repo (with queued lastScan) */
export async function addRepo({ url }) {
  if (USE_FAKE_API) return (await fake()).addRepo({ url });
  const data = await request('/scan/addRepo', {
    method: 'POST',
    body: { url: String(url || '').trim() },
  });
  return toRepo(data?.repo || data, data?.scan || null);
}

/** Delete repository (supported in fake mode; backend endpoint not implemented yet). */
export async function deleteRepo(repoId) {
  if (USE_FAKE_API) return (await fake()).deleteRepo(repoId);
  throw new ApiError('Removing repositories is not supported by the backend yet.', {
    code: 'NOT_IMPLEMENTED',
    status: 501,
  });
}

/** POST /scan/refreshRepo/:repoId -> normalized scan object */
export async function triggerScan(repoId) {
  if (USE_FAKE_API) return (await fake()).triggerScan(repoId);
  const data = await request(`/scan/refreshRepo/${encodeURIComponent(repoId)}`, { method: 'POST' });
  return toScan(data?.scan || data);
}
