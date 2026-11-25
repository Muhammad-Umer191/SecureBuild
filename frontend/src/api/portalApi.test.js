import { describe, it, expect, vi, afterEach } from 'vitest';
import { login, register, getMe, logout } from './auth.js';
import { validateRepoUrl, listRepos, addRepo, deleteRepo, triggerScan } from './repos.js';
import { listScans } from './scans.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe('validateRepoUrl', () => {
  it('accepts valid github.com URLs and trims trailing slash', () => {
    expect(validateRepoUrl(' https://github.com/acme/demo-repo/ ')).toEqual({
      valid: true,
      normalizedUrl: 'https://github.com/acme/demo-repo',
      name: 'acme/demo-repo',
      error: null,
    });
  });

  it('rejects empty or non-GitHub URLs', () => {
    expect(validateRepoUrl('').valid).toBe(false);
    expect(validateRepoUrl('http://github.com/acme/demo').valid).toBe(false);
    expect(validateRepoUrl('https://gitlab.com/acme/demo').valid).toBe(false);
  });
});

describe('portal API clients (HTTP mode)', () => {
  it('login stores token, getMe returns user, and logout clears token', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: 'jwt-abc', user: { id: '1', role: 'admin' } }), { status: 200 }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ user: { id: '1', role: 'admin' } }), { status: 200 }),
      );
    vi.stubGlobal('fetch', fetchMock);

    await login({ email: 'a@b.com', password: 'password123' });
    expect(window.localStorage.getItem('sb_token')).toBe('jwt-abc');

    const me = await getMe();
    expect(me).toEqual({ id: '1', role: 'admin' });

    logout();
    expect(window.localStorage.getItem('sb_token')).toBeNull();
    await expect(getMe()).resolves.toBeNull();
  });

  it('register stores returned token', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ token: 'jwt-new', user: { id: '2', role: 'analyst' } }), { status: 201 }),
      ),
    );
    await register({ name: 'Ahsan', email: 'ahsan@b.com', password: 'password123' });
    expect(window.localStorage.getItem('sb_token')).toBe('jwt-new');
  });

  it('calls expected endpoints for repos and scans', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify([{ id: 'r1' }]), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'r2' }), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 's1' }), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([{ id: 's1' }]), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ deleted: true }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(listRepos()).resolves.toEqual({ items: [{ id: 'r1' }] });
    await addRepo({ url: 'https://github.com/acme/app' });
    await triggerScan('r2');
    await expect(listScans('r2')).resolves.toEqual({ items: [{ id: 's1' }] });
    await deleteRepo('r2');

    expect(fetchMock.mock.calls.map(([url, init]) => [init?.method || 'GET', url])).toEqual([
      ['GET', '/api/repos'],
      ['POST', '/api/repos'],
      ['POST', '/api/repos/r2/scans'],
      ['GET', '/api/repos/r2/scans'],
      ['DELETE', '/api/repos/r2'],
    ]);
  });
});
