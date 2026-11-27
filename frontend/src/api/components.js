import { apiFetch, request, USE_FAKE_API } from './client.js';

const fake = () => import('./fake/index.js');

/** GET /component/show/:repoId -> { scan, items, page, limit, total, summary } */
export async function listComponents(repoId, params = {}) {
  if (USE_FAKE_API) return (await fake()).listComponents(repoId, params);
  const res = await request(`/component/show/${encodeURIComponent(repoId)}`, { query: params });
  return { ...res, items: (res.items || []).map((c) => ({ ...c, id: String(c.id ?? c._id) })) };
}

export function filenameFromDisposition(header) {
  if (!header) return null;
  const star = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(header);
  if (star) {
    try {
      return sanitizeFilename(decodeURIComponent(star[1].trim()));
    } catch {
      /* fall through */
    }
  }
  const m = /filename\s*=\s*"?([^";]+)"?/i.exec(header);
  return m ? sanitizeFilename(m[1].trim()) : null;
}

function sanitizeFilename(name) {
  const clean = name.replace(/[\/:*?"<>|\x00-\x1f]/g, '_');
  return clean || null;
}

/** GET /component/export/:repoId?format=cyclonedx -> { blob, filename } (always the latest scan) */
export async function exportSbom(repoId, { scanId } = {}) {
  if (USE_FAKE_API) return (await fake()).exportSbom(repoId, { scanId });
  const res = await apiFetch(`/component/export/${encodeURIComponent(repoId)}`, {
    query: { format: 'cyclonedx' },
    headers: { Accept: 'application/json' },
  });
  const blob = await res.blob();
  const filename = filenameFromDisposition(res.headers.get('Content-Disposition')) || 'sbom.cdx.json';
  return { blob, filename };
}
