// Fallback lookup: CVE id -> score, from cvelistV5 (https://github.com/CVEProject/cvelistV5).
//
// Used when OSV gives a finding a CVE alias but no CVSS score. Safety:
//   - the id is checked against a strict pattern before any URL is built
//   - fixed https host from config, redirects refused, origin re-checked
//   - hard timeout and a response-size cap
//   - results and "not found" are cached in MongoDB with a TTL
//   - concurrent lookups of the same id share one request
const ApiError = require('../../utils/ApiError');
const logger = require('../../utils/logger');
const CveCache = require('../../models/CveCache');
const { CveRecordError, cveRecordPath, normalizeCveId, parseCveRecord } = require('./cveRecord');

const HOUR = 60 * 60 * 1000;
const DEFAULTS = {
  baseUrl: process.env.CVELIST_BASE_URL || 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves',
  ttlMs: 24 * HOUR,
  negativeTtlMs: HOUR,
  timeoutMs: 5000,
  maxBytes: 2 * 1024 * 1024, // the biggest records (log4j) are ~200 KB
};

const unavailable = (msg = 'CVE database is unavailable, try again later') =>
  new ApiError(502, 'UPSTREAM_UNAVAILABLE', msg);

/** MongoDB-backed cache. */
const mongoCache = {
  get: (cveId) => CveCache.findOne({ cveId }).lean(),
  set: (cveId, entry) => CveCache.updateOne({ cveId }, { $set: { cveId, ...entry } }, { upsert: true }),
};

/** In-memory cache (tests, scripts). */
function memoryCache() {
  const map = new Map();
  return {
    map,
    get: async (cveId) => map.get(cveId) || null,
    set: async (cveId, entry) => { map.set(cveId, { cveId, ...entry }); },
  };
}

async function readCapped(response, maxBytes) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) throw new Error('CVE record too large');
  if (!response.body) return response.text();
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    // eslint-disable-next-line no-await-in-loop
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error('CVE record too large');
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString('utf8');
}

function createCveLookup(options = {}) {
  const {
    baseUrl, ttlMs, negativeTtlMs, timeoutMs, maxBytes,
  } = { ...DEFAULTS, ...options };
  const cache = options.cache || mongoCache;
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const now = options.now || (() => new Date());

  const base = new URL(baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`);
  if (base.protocol !== 'https:') throw new Error('CVELIST_BASE_URL must use https');
  const inFlight = new Map();

  async function fetchRecord(cveId) {
    const url = new URL(cveRecordPath(cveId), base);
    if (url.origin !== base.origin) throw new Error('Refusing to leave the configured host');
    let response;
    try {
      response = await fetchImpl(url, {
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
        headers: { accept: 'application/json', 'user-agent': 'SecureBuild-cve-lookup' },
      });
    } catch (err) {
      logger.warn(`[cveLookup] ${cveId}: network error (${err.name})`);
      throw unavailable();
    }
    if (response.status === 404) return { found: false };
    if (!response.ok) {
      logger.warn(`[cveLookup] ${cveId}: upstream HTTP ${response.status}`);
      throw unavailable();
    }
    try {
      const text = await readCapped(response, maxBytes);
      return { found: true, data: parseCveRecord(JSON.parse(text), cveId) };
    } catch (err) {
      const why = err instanceof CveRecordError || err instanceof SyntaxError ? 'bad record' : err.message;
      logger.warn(`[cveLookup] ${cveId}: ${why}`);
      throw unavailable('CVE database returned an unusable record');
    }
  }

  async function resolve(cveId) {
    const t = now();
    const cached = await cache.get(cveId);
    if (cached && new Date(cached.expiresAt) > t) {
      if (!cached.found) return null;
      return { ...cached.data, fetchedAt: new Date(cached.fetchedAt).toISOString(), cached: true };
    }
    const result = await fetchRecord(cveId);
    const expiresAt = new Date(t.getTime() + (result.found ? ttlMs : negativeTtlMs));
    await cache.set(cveId, { found: result.found, data: result.data || null, fetchedAt: t, expiresAt });
    return result.found ? { ...result.data, fetchedAt: t.toISOString(), cached: false } : null;
  }

  return {
    /**
     * @returns {Promise<Object|null>} parsed CVE info, or null when the CVE does not exist
     * @throws ApiError 400 VALIDATION_ERROR (bad id) | 502 UPSTREAM_UNAVAILABLE
     */
    lookup(rawId) {
      const cveId = normalizeCveId(rawId);
      if (!cveId) return Promise.reject(new ApiError(400, 'VALIDATION_ERROR', 'cveId must look like CVE-2021-44228'));
      if (inFlight.has(cveId)) return inFlight.get(cveId);
      const p = resolve(cveId).finally(() => inFlight.delete(cveId));
      inFlight.set(cveId, p);
      return p;
    },
  };
}

module.exports = { createCveLookup, memoryCache, mongoCache };
