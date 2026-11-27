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

describe('portal API clients (live backend routes)', () => {
  it('login stores token, defaults missing role to analyst, and logout clears token', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: 'jwt-abc', user: { id: '1', name: 'Ahsan', email: 'a@b.com' } }), {
          status: 200,
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ user: { id: '1', name: 'Ahsan', email: 'a@b.com' } }), { status: 200 }),
      );
    vi.stubGlobal('fetch', fetchMock);

    const logged = await login({ email: 'a@b.com', password: 'password123' });
    expect(window.localStorage.getItem('sb_token')).toBe('jwt-abc');
    expect(logged.user.role).toBe('analyst');

    const me = await getMe();
    expect(me).toMatchObject({ id: '1', name: 'Ahsan', role: 'analyst' });

    logout();
    expect(window.localStorage.getItem('sb_token')).toBeNull();
    await expect(getMe()).resolves.toBeNull();
  });

  it('register stores returned token and normalizes user', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ token: 'jwt-new', user: { _id: 'u2', name: 'Ahsan' } }), { status: 201 }),
      ),
    );
    const res = await register({ name: 'Ahsan', email: 'ahsan@b.com', password: 'password123' });
    expect(window.localStorage.getItem('sb_token')).toBe('jwt-new');
    expect(res.user).toMatchObject({ id: 'u2', role: 'analyst' });
  });

  it('calls /api/scan/* endpoints and normalizes Mongo _id fields', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ items: [{ _id: 'r1', name: 'acme/app', lastScan: { _id: 's0', status: 'completed' } }] }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ repo: { _id: 'r2', name: 'acme/new' }, scan: { _id: 's1', status: 'queued' } }),
          { status: 201 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ repo: { _id: 'r2' }, scan: { _id: 's2', status: 'queued' } }), { status: 202 }),
      );
    vi.stubGlobal('fetch', fetchMock);

    const listed = await listRepos();
    expect(listed.items[0]).toMatchObject({ id: 'r1', lastScan: { id: 's0', status: 'completed' } });

    const added = await addRepo({ url: 'https://github.com/acme/new' });
    expect(added).toMatchObject({ id: 'r2', lastScan: { id: 's1', status: 'queued' } });

    const scan = await triggerScan('r2');
    expect(scan).toMatchObject({ id: 's2', status: 'queued' });

    expect(fetchMock.mock.calls.map(([url, init]) => [init?.method || 'GET', url])).toEqual([
      ['GET', '/api/scan/fetchRepos'],
      ['POST', '/api/scan/addRepo'],
      ['POST', '/api/scan/refreshRepo/r2'],
    ]);

    const history = await listScans('r2', scan);
    expect(history).toEqual({ items: [scan], limitedToLatest: true });

    await expect(deleteRepo('r2')).rejects.toMatchObject({ code: 'NOT_IMPLEMENTED', status: 501 });
  });
});
