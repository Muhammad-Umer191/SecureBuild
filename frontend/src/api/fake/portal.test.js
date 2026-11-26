import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  login,
  register,
  getMe,
  listRepos,
  addRepo,
  deleteRepo,
  triggerScan,
  listScans,
  resetFakePortalState,
} from './portal.js';

describe('fake portal API', () => {
  beforeEach(() => {
    resetFakePortalState();
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it('logs in seeded users and restores session via getMe', async () => {
    const res = await login({ email: 'analyst@securebuild.dev', password: 'password123' });
    expect(res.user).toMatchObject({ email: 'analyst@securebuild.dev', role: 'analyst' });
    expect(res.token).toMatch(/^fake-token:/);

    window.localStorage.setItem('sb_token', res.token);
    await expect(getMe()).resolves.toMatchObject({ email: 'analyst@securebuild.dev', role: 'analyst' });
  });

  it('rejects bad login credentials and missing sessions', async () => {
    await expect(login({ email: 'analyst@securebuild.dev', password: 'wrong' })).rejects.toMatchObject({
      status: 401,
      code: 'INVALID_CREDENTIALS',
    });
    await expect(getMe()).rejects.toMatchObject({ status: 401, code: 'AUTH_INVALID' });
  });

  it('registers a new analyst and blocks duplicate emails', async () => {
    const created = await register({
      name: 'Iqra',
      email: 'iqra@securebuild.dev',
      password: 'password123',
    });
    expect(created.user).toMatchObject({ name: 'Iqra', role: 'analyst' });

    await expect(
      register({ name: 'Dup', email: 'iqra@securebuild.dev', password: 'password123' }),
    ).rejects.toMatchObject({ status: 409, code: 'EMAIL_EXISTS' });
  });

  it('adds, lists, scans, and removes repositories', async () => {
    const initial = await listRepos();
    expect(initial.items).toHaveLength(2);

    const added = await addRepo({ url: 'https://github.com/octocat/Hello-World/' });
    expect(added).toMatchObject({
      name: 'octocat/Hello-World',
      url: 'https://github.com/octocat/Hello-World',
    });

    await expect(addRepo({ url: 'https://github.com/octocat/Hello-World' })).rejects.toMatchObject({
      status: 409,
      code: 'DUPLICATE_REPO',
    });
    await expect(addRepo({ url: 'https://gitlab.com/octocat/Hello-World' })).rejects.toMatchObject({
      status: 400,
      code: 'VALIDATION_ERROR',
    });

    const scan = await triggerScan(added.id);
    expect(scan.status).toBe('completed');
    const history = await listScans(added.id);
    expect(history.items).toHaveLength(2);

    await deleteRepo(added.id);
    expect((await listRepos()).items).toHaveLength(2);
    await expect(listScans(added.id)).rejects.toMatchObject({ status: 404, code: 'NOT_FOUND' });
  });
});
