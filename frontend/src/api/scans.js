import { USE_FAKE_API } from './client.js';

const fake = () => import('./fake/portal.js');

/**
 * Fetch scan runs for a repository.
 * In fake mode, returns full mock history.
 * In live mode, falls back to the repo's latest scan until a backend history route is added.
 */
export async function listScans(repoId, latestScan = null) {
  if (USE_FAKE_API) return (await fake()).listScans(repoId);
  return {
    items: latestScan ? [latestScan] : [],
    limitedToLatest: true,
  };
}
