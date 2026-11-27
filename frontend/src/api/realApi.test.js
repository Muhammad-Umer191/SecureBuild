// Real-mode (VITE_USE_FAKE_API not "true") calls of the F2 API modules:
// right backend paths, auth header, and Mongo documents turned into UI shapes.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { USE_FAKE_API } from './client.js';
import { getFinding, listFindings, toFinding, updateFinding } from './findings.js';
import { exportSbom, listComponents } from './components.js';

const json = (body, init = {}) => new Response(JSON.stringify(body), {
  status: 200, headers: { 'Content-Type': 'application/json' }, ...init,
});

let fetchMock;
beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
  window.localStorage.setItem('sb_token', 'tok123');
});
afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

const calledUrl = () => fetchMock.mock.calls[0][0];
const calledInit = () => fetchMock.mock.calls[0][1];

describe.skipIf(USE_FAKE_API)('F2 API modules against the real backend', () => {
  it('lists findings from /vulnerability/filter/:repoId with filters', async () => {
    fetchMock.mockResolvedValue(json({ items: [{ id: 'a1', vulnId: 'GHSA-1' }], total: 1, counts: {} }));
    const res = await listFindings('r1', { severity: ['critical', 'high'], status: 'open', page: 2 });
    expect(calledUrl()).toBe('/api/vulnerability/filter/r1?severity=critical%2Chigh&status=open&page=2');
    expect(calledInit().headers.Authorization).toBe('Bearer tok123');
    expect(res.items[0].id).toBe('a1');
  });

  it('gets one finding from /vulnerability/:id and maps _id to id', async () => {
    fetchMock.mockResolvedValue(json({
      _id: '665f', __v: 0, vulnId: 'GHSA-1', status: 'ignored',
      ignore: { reason: 'Dev only', by: '664a', at: '2026-11-20T00:00:00Z' }, fixedVersions: ['1.2.3'],
    }));
    const f = await getFinding('665f');
    expect(calledUrl()).toBe('/api/vulnerability/665f');
    expect(f).toMatchObject({ id: '665f', hasFix: true, cves: [], ignore: { by: '664a' } });
    expect(f).not.toHaveProperty('_id');
    expect(f).not.toHaveProperty('__v');
  });

  it('PATCHes /vulnerability/:id to ignore', async () => {
    fetchMock.mockResolvedValue(json({ _id: '665f', status: 'ignored' }));
    await updateFinding('665f', { status: 'ignored', reason: 'Only in tests' });
    expect(calledUrl()).toBe('/api/vulnerability/665f');
    expect(calledInit()).toMatchObject({ method: 'PATCH', body: JSON.stringify({ status: 'ignored', reason: 'Only in tests' }) });
  });

  it('encodes ids so they cannot change the path', async () => {
    fetchMock.mockResolvedValue(json({ _id: 'x' }));
    await getFinding('../auth/me');
    expect(calledUrl()).toBe('/api/vulnerability/..%2Fauth%2Fme');
  });

  it('lists components from /component/show/:repoId', async () => {
    fetchMock.mockResolvedValue(json({ items: [{ _id: 'c1', name: 'qs' }], total: 1, summary: {} }));
    const res = await listComponents('r1', { vulnerable: 'true', sort: 'vulns' });
    expect(calledUrl()).toBe('/api/component/show/r1?vulnerable=true&sort=vulns');
    expect(res.items[0].id).toBe('c1');
  });

  it('downloads the SBOM from /component/export/:repoId', async () => {
    fetchMock.mockResolvedValue(new Response('{"bomFormat":"CycloneDX"}', {
      status: 200, headers: { 'Content-Disposition': 'attachment; filename="acme-shop-sbom.cdx.json"' },
    }));
    const { blob, filename } = await exportSbom('r1');
    expect(calledUrl()).toBe('/api/component/export/r1?format=cyclonedx');
    expect(filename).toBe('acme-shop-sbom.cdx.json');
    expect(await blob.text()).toContain('CycloneDX');
  });

  it('turns backend errors into ApiError with the code', async () => {
    fetchMock.mockResolvedValue(json({ error: { code: 'NOT_FOUND', message: 'Vulnerability not found' } }, { status: 404 }));
    await expect(getFinding('nope')).rejects.toMatchObject({ code: 'NOT_FOUND', status: 404 });
  });
});

describe('toFinding', () => {
  it('leaves already-mapped findings alone', () => {
    expect(toFinding({ id: 'a', cves: [{ cveId: 'CVE-2024-1' }], hasFix: false })).toEqual({
      id: 'a', cves: [{ cveId: 'CVE-2024-1' }], hasFix: false,
    });
  });
});
