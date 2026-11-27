// Unit tests: the cvelistV5 fetcher (fake network, in-memory cache).
const fs = require('node:fs');
const path = require('node:path');
const { createCveLookup, memoryCache } = require('../../src/services/cve/cveLookup');

const log4j = fs.readFileSync(path.join(__dirname, 'fixtures', 'CVE-2021-44228.json'), 'utf8');

const jsonResponse = (body, status = 200, headers = {}) => new Response(body, {
  status, headers: { 'content-type': 'application/json', ...headers },
});

function setup(fetchImpl, opts = {}) {
  const cache = memoryCache();
  let t = new Date('2026-11-27T10:00:00Z');
  const lookup = createCveLookup({ cache, fetchImpl, now: () => t, ...opts });
  return { lookup, cache, advance: (ms) => { t = new Date(t.getTime() + ms); } };
}

describe('cveLookup', () => {
  test('fetches the right cvelistV5 file and parses the score', async () => {
    const fetchImpl = jest.fn(async () => jsonResponse(log4j));
    const { lookup } = setup(fetchImpl);
    const r = await lookup.lookup('cve-2021-44228');
    expect(String(fetchImpl.mock.calls[0][0])).toBe(
      'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/44xxx/CVE-2021-44228.json',
    );
    expect(fetchImpl.mock.calls[0][1]).toMatchObject({ redirect: 'error' });
    expect(r).toMatchObject({ cveId: 'CVE-2021-44228', score: 10, severity: 'critical', cached: false });
  });

  test('serves repeats from the cache until the TTL runs out', async () => {
    const fetchImpl = jest.fn(async () => jsonResponse(log4j));
    const { lookup, advance } = setup(fetchImpl, { ttlMs: 1000 });
    await lookup.lookup('CVE-2021-44228');
    expect((await lookup.lookup('CVE-2021-44228')).cached).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    advance(1001);
    await lookup.lookup('CVE-2021-44228');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  test('caches "not found" too', async () => {
    const fetchImpl = jest.fn(async () => new Response('404: Not Found', { status: 404 }));
    const { lookup, cache } = setup(fetchImpl);
    expect(await lookup.lookup('CVE-2099-99999')).toBeNull();
    expect(await lookup.lookup('CVE-2099-99999')).toBeNull();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(cache.map.get('CVE-2099-99999').found).toBe(false);
  });

  test('concurrent lookups of one id share a single request', async () => {
    const fetchImpl = jest.fn(async () => jsonResponse(log4j));
    const { lookup } = setup(fetchImpl);
    await Promise.all([lookup.lookup('CVE-2021-44228'), lookup.lookup('CVE-2021-44228'), lookup.lookup('cve-2021-44228')]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  test.each(['CVE-2021-44228/../../x', 'http://evil.example/', 'CVE-2021-1', '%2e%2e%2f'])(
    'rejects %s before any network call',
    async (bad) => {
      const fetchImpl = jest.fn();
      const { lookup } = setup(fetchImpl);
      await expect(lookup.lookup(bad)).rejects.toMatchObject({ code: 'VALIDATION_ERROR', status: 400 });
      expect(fetchImpl).not.toHaveBeenCalled();
    },
  );

  test('network errors become UPSTREAM_UNAVAILABLE', async () => {
    const { lookup } = setup(async () => { throw new TypeError('fetch failed'); });
    await expect(lookup.lookup('CVE-2021-44228')).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE', status: 502 });
  });

  test('a slow upstream times out', async () => {
    const fetchImpl = (_url, { signal }) => new Promise((_res, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason));
    });
    const { lookup } = setup(fetchImpl, { timeoutMs: 50 });
    await expect(lookup.lookup('CVE-2021-44228')).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
  });

  test('upstream 5xx is not cached', async () => {
    const { lookup, cache } = setup(async () => new Response('oops', { status: 503 }));
    await expect(lookup.lookup('CVE-2021-44228')).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
    expect(cache.map.size).toBe(0);
  });

  test('oversized responses are refused (declared and streamed)', async () => {
    const big = 'x'.repeat(5000);
    const declared = setup(async () => jsonResponse(big, 200, { 'content-length': '999999999' }), { maxBytes: 1000 });
    await expect(declared.lookup.lookup('CVE-2021-44228')).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
    const streamed = setup(async () => jsonResponse(big), { maxBytes: 1000 });
    await expect(streamed.lookup.lookup('CVE-2021-44228')).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
  });

  test('non-JSON and wrong-CVE records are refused', async () => {
    const html = setup(async () => new Response('<html>hi</html>', { status: 200 }));
    await expect(html.lookup.lookup('CVE-2021-44228')).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
    const wrong = setup(async () => jsonResponse(log4j));
    await expect(wrong.lookup.lookup('CVE-2022-24999')).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
  });

  test('only an https base URL is allowed', () => {
    expect(() => createCveLookup({ baseUrl: 'http://example.com/cves', cache: memoryCache() })).toThrow(/https/);
  });
});
