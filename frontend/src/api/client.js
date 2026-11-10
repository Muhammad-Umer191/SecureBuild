// Thin fetch wrapper for the SecureBuild API.
// Base URL comes from VITE_API_URL (default "/api"). Errors are normalised to ApiError.

export const API_BASE = (import.meta.env?.VITE_API_URL || '/api').replace(/\/+$/, '');
export const USE_FAKE_API = import.meta.env?.VITE_USE_FAKE_API === 'true';

export class ApiError extends Error {
  constructor(message, { code = 'INTERNAL_ERROR', status = 0 } = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

export function getToken() {
  try {
    return window.localStorage.getItem('sb_token');
  } catch {
    return null;
  }
}

export function buildQuery(params) {
  const sp = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v === undefined || v === null || v === '') return;
    if (Array.isArray(v)) {
      if (v.length) sp.set(k, v.join(','));
    } else {
      sp.set(k, String(v));
    }
  });
  const s = sp.toString();
  return s ? `?${s}` : '';
}

async function toApiError(res) {
  let code = 'INTERNAL_ERROR';
  let message = `Request failed (${res.status})`;
  try {
    const body = await res.json();
    if (body?.error) {
      code = body.error.code || code;
      message = body.error.message || message;
    }
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(message, { code, status: res.status });
}

/** Low-level: returns the Response (used for file downloads). Throws ApiError on non-2xx. */
export async function apiFetch(path, { method = 'GET', body, query, headers = {} } = {}) {
  const h = { Accept: 'application/json', ...headers };
  const token = getToken();
  if (token) h.Authorization = `Bearer ${token}`;
  if (body !== undefined) h['Content-Type'] = 'application/json';

  let res;
  try {
    res = await fetch(`${API_BASE}${path}${buildQuery(query)}`, {
      method,
      headers: h,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError('Could not reach the server', { code: 'NETWORK_ERROR', status: 0 });
  }
  if (!res.ok) throw await toApiError(res);
  return res;
}

export async function request(path, opts) {
  const res = await apiFetch(path, opts);
  return res.json();
}
