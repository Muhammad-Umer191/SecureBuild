import { request, USE_FAKE_API } from './client.js';

const fake = () => import('./fake/index.js');

const enc = encodeURIComponent;

/**
 * The backend returns Mongo documents (`_id`, ObjectId refs). The UI works with `id`
 * and plain strings, so every finding goes through here.
 */
export function toFinding(doc) {
  if (!doc || typeof doc !== 'object') return doc;
  const { _id, __v, ...rest } = doc;
  const out = { ...rest, id: String(rest.id ?? _id) };
  if (rest.ignore) out.ignore = { ...rest.ignore, by: rest.ignore.by != null ? String(rest.ignore.by) : null };
  if (!Array.isArray(out.cves)) out.cves = [];
  if (out.hasFix === undefined) out.hasFix = (out.fixedVersions || []).length > 0;
  return out;
}

/** GET /vulnerability/filter/:repoId -> { scan, items, page, limit, total, counts } */
export async function listFindings(repoId, params = {}) {
  if (USE_FAKE_API) return (await fake()).listFindings(repoId, params);
  const res = await request(`/vulnerability/filter/${enc(repoId)}`, { query: params });
  return { ...res, items: (res.items || []).map(toFinding) };
}

/** GET /vulnerability/:findingId (the server fills in CVE details from cvelistV5) */
export async function getFinding(findingId) {
  if (USE_FAKE_API) return (await fake()).getFinding(findingId);
  return toFinding(await request(`/vulnerability/${enc(findingId)}`));
}

/** PATCH /vulnerability/:findingId  body: {status:'ignored', reason} | {status:'open'} */
export async function updateFinding(findingId, body) {
  if (USE_FAKE_API) return (await fake()).updateFinding(findingId, body);
  return toFinding(await request(`/vulnerability/${enc(findingId)}`, { method: 'PATCH', body }));
}
