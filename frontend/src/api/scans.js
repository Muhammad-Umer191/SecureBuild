import { request, USE_FAKE_API } from './client.js';

const fake = () => import('./fake/portal.js');

/** GET /repos/:repoId/scans -> { items: [...] } */
export async function listScans(repoId) {
  if (USE_FAKE_API) return (await fake()).listScans(repoId);
  const data = await request(`/repos/${encodeURIComponent(repoId)}/scans`);
  return Array.isArray(data) ? { items: data } : data;
}
