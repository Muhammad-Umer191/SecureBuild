import { request, USE_FAKE_API } from './client.js';

const fake = () => import('./fake/index.js');

/** GET /repos/:repoId/findings */
export async function listFindings(repoId, params = {}) {
  if (USE_FAKE_API) return (await fake()).listFindings(repoId, params);
  return request(`/repos/${encodeURIComponent(repoId)}/findings`, { query: params });
}

/** GET /findings/:findingId */
export async function getFinding(findingId) {
  if (USE_FAKE_API) return (await fake()).getFinding(findingId);
  return request(`/findings/${encodeURIComponent(findingId)}`);
}

/** PATCH /findings/:findingId  body: {status:'ignored', reason} | {status:'open'} */
export async function updateFinding(findingId, body) {
  if (USE_FAKE_API) return (await fake()).updateFinding(findingId, body);
  return request(`/findings/${encodeURIComponent(findingId)}`, { method: 'PATCH', body });
}
