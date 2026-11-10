import { describe, it, expect, vi, afterEach } from 'vitest';
import { request, ApiError, getToken, buildQuery } from './client.js';
import { filenameFromDisposition } from './components.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe('api client', () => {
  it('sends the bearer token from localStorage and parses JSON', async () => {
    window.localStorage.setItem('sb_token', 'tok123');
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: 1 }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(request('/x', { query: { a: ['b', 'c'], skip: undefined, e: '' } })).resolves.toEqual({ ok: 1 });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/x?a=b%2Cc');
    expect(init.headers.Authorization).toBe('Bearer tok123');
  });

  it('maps the error envelope to ApiError', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: { code: 'NO_SCAN', message: 'No scan' } }), { status: 404 }),
    ));
    const err = await request('/x').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ code: 'NO_SCAN', status: 404, message: 'No scan' });
  });

  it('survives non-JSON error bodies and network failures', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<html>', { status: 502 })));
    expect(await request('/x').catch((e) => e)).toMatchObject({ code: 'INTERNAL_ERROR', status: 502 });
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('failed')));
    expect(await request('/x').catch((e) => e)).toMatchObject({ code: 'NETWORK_ERROR', status: 0 });
  });

  it('getToken never throws when storage is blocked', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    expect(getToken()).toBeNull();
  });

  it('buildQuery skips empty values', () => {
    expect(buildQuery({ a: 1, b: '', c: null, d: [] })).toBe('?a=1');
    expect(buildQuery({})).toBe('');
  });
});

describe('filenameFromDisposition', () => {
  it('reads quoted and RFC 5987 filenames and sanitises path characters', () => {
    expect(filenameFromDisposition('attachment; filename="acme-repo-sbom.cdx.json"')).toBe('acme-repo-sbom.cdx.json');
    expect(filenameFromDisposition("attachment; filename*=UTF-8''a%20b.json")).toBe('a b.json');
    expect(filenameFromDisposition('attachment; filename="../../evil.json"')).toBe('.._.._evil.json');
    expect(filenameFromDisposition(null)).toBeNull();
  });
});
