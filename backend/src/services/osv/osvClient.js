// Small HTTP client for the OSV.dev API (https://google.github.io/osv.dev/api/).
//
// - Every request has a timeout (30s).
// - Network errors, timeouts, 429 (rate limited) and 5xx (server trouble) are
//   retried up to 4 attempts with exponential backoff (0.5s, 1s, 2s + jitter).
//   A Retry-After header from the server is honoured, up to 30s.
// - Other 4xx answers are not retried: they are returned to the caller, which
//   decides (e.g. 404 = unknown advisory).
// - `fetch` and `sleep` can be injected, so tests run offline and instantly.

const OSV_API = 'https://api.osv.dev/v1';

/** OSV.dev failed or answered something unusable. `permanent` = retrying won't help. */
class OsvError extends Error {
  constructor(code, message, { permanent = false } = {}) {
    super(message);
    this.name = 'OsvError';
    this.code = code;
    this.permanent = permanent;
  }
}

const isRetryable = (status) => status === 429 || status >= 500;
const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function readJson(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * @param {Object} [opts]
 * @param {Function} [opts.fetch]        default: global fetch
 * @param {string} [opts.baseUrl]        default: https://api.osv.dev/v1
 * @param {number} [opts.timeoutMs=30000]
 * @param {number} [opts.maxAttempts=4]
 * @param {number} [opts.baseDelayMs=500]
 * @param {number} [opts.maxRetryAfterMs=30000]
 * @param {(ms: number) => Promise<void>} [opts.sleep]
 * @returns {{postJson: Function, getJson: Function}}
 *   each resolves to { status, body } for 2xx and non-retryable 4xx answers
 */
function createOsvClient({
  fetch = globalThis.fetch,
  baseUrl = OSV_API,
  timeoutMs = 30_000,
  maxAttempts = 4,
  baseDelayMs = 500,
  maxRetryAfterMs = 30_000,
  sleep = defaultSleep,
} = {}) {
  const backoff = (attempt) => baseDelayMs * 2 ** (attempt - 1) + Math.random() * (baseDelayMs / 2);

  // Retry-After in seconds when the server sends a usable one, otherwise backoff.
  // (A missing header must not count as "0 seconds".)
  function retryDelay(res, attempt) {
    const header = res.headers.get('retry-after');
    const seconds = header !== null && /^\d+$/.test(header.trim()) ? Number(header) : NaN;
    if (Number.isFinite(seconds)) return Math.min(seconds * 1000, maxRetryAfterMs);
    return backoff(attempt);
  }

  async function request(method, path, body) {
    let lastProblem = 'unknown error';
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      let res;
      try {
        res = await fetch(`${baseUrl}${path}`, {
          method,
          headers: body === undefined ? { accept: 'application/json' } : { 'content-type': 'application/json', accept: 'application/json' },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (err) {
        lastProblem = err.name === 'TimeoutError' ? `timed out after ${timeoutMs / 1000}s` : `network error (${err.message})`;
        if (attempt < maxAttempts) await sleep(backoff(attempt));
        continue;
      }

      if (res.ok) {
        const json = await readJson(res);
        if (json === null) throw new OsvError('OSV_BAD_RESPONSE', `OSV.dev ${method} ${path}: response is not valid JSON`);
        return { status: res.status, body: json };
      }
      if (!isRetryable(res.status)) return { status: res.status, body: await readJson(res) };

      lastProblem = `HTTP ${res.status}`;
      if (attempt < maxAttempts) await sleep(retryDelay(res, attempt));
    }
    throw new OsvError('OSV_UNAVAILABLE', `OSV.dev ${method} ${path} failed after ${maxAttempts} attempts (${lastProblem})`);
  }

  return {
    postJson: (path, body) => request('POST', path, body),
    getJson: (path) => request('GET', path),
  };
}

module.exports = { createOsvClient, OsvError, OSV_API };
