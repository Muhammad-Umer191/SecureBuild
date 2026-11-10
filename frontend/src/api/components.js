import { apiFetch, request, USE_FAKE_API } from './client.js';

const fake = () => import('./fake/index.js');

/** GET /repos/:repoId/components */
export async function listComponents(repoId, params = {}) {
  if (USE_FAKE_API) return (await fake()).listComponents(repoId, params);
  return request(`/repos/${encodeURIComponent(repoId)}/components`, { query: params });
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

/** GET /repos/:repoId/sbom?format=cyclonedx -> { blob, filename } */
export async function exportSbom(repoId, { scanId } = {}) {
  if (USE_FAKE_API) return (await fake()).exportSbom(repoId, { scanId });
  const res = await apiFetch(`/repos/${encodeURIComponent(repoId)}/sbom`, {
    query: { format: 'cyclonedx', scanId },
    headers: { Accept: 'application/json' },
  });
  const blob = await res.blob();
  const filename = filenameFromDisposition(res.headers.get('Content-Disposition')) || 'sbom.cdx.json';
  return { blob, filename };
}
