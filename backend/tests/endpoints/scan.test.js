// tests/endpoints/scan.test.js – covers POST /api/scan/addRepo, GET /fetchRepos, POST /refreshRepo/:repoId
// The real scanner pipeline is mocked so tests are fast and offline.
const request = require('supertest');
const app     = require('../../src/app');

// ── mock the scanner service and worker so no git/OSV calls happen ───────────
jest.mock('../../src/services/scannerService', () => ({
  scanRepository: jest.fn().mockResolvedValue({
    commitSha:  'abc1234def5678',
    findings:   [],
    components: [],
  }),
}));

jest.mock('../../src/worker/index', () => ({
  dispatchScanJob: jest.fn((payload) => {
    // Simulate the background worker completing synchronously via mongoose
    setImmediate(async () => {
      const mongoose = require('mongoose');
      const { Repo, Scan } = require('../../src/models');
      try {
        const scan = await Scan.findById(payload.scanId);
        const repo = await Repo.findById(payload.repoId);
        if (scan) { scan.status = 'completed'; scan.commitSha = 'abc123'; scan.finishedAt = new Date(); await scan.save(); }
        if (repo)  { repo.status = 'idle'; repo.lastScan = payload.scanId; await repo.save(); }
      } catch (_) { /* ignore in tests */ }
    });
    return { on: jest.fn(), send: jest.fn(), unref: jest.fn() };
  }),
}));

// ── helper: register and return a token ─────────────────────────────────────
let userCount = 0;
async function getToken() {
  userCount += 1;
  const email = `scan_user_${userCount}_${Date.now()}@test.com`;
  const res = await request(app).post('/api/auth/register')
    .send({ name: 'Scan User', email, password: 'Password1!' });
  return res.body.token;
}

// ── POST /api/scan/addRepo ───────────────────────────────────────────────────
describe('Scan – POST /api/scan/addRepo', () => {
  it('adds a valid GitHub repo and queues a scan', async () => {
    const token = await getToken();
    const res = await request(app).post('/api/scan/addRepo')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://github.com/acme/my-repo' });

    expect(res.status).toBe(201);
    expect(res.body.repo.name).toBe('acme/my-repo');
    expect(res.body.repo.status).toBe('scanning');
    expect(res.body.scan.status).toBe('queued');
  });

  it('rejects a non-GitHub URL', async () => {
    const token = await getToken();
    const res = await request(app).post('/api/scan/addRepo')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://gitlab.com/acme/my-repo' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('rejects a duplicate repo for the same user', async () => {
    const token = await getToken();
    await request(app).post('/api/scan/addRepo')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://github.com/acme/dup-repo' });
    const res = await request(app).post('/api/scan/addRepo')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://github.com/acme/dup-repo' });
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('DUPLICATE');
  });

  it('requires authentication', async () => {
    const res = await request(app).post('/api/scan/addRepo')
      .send({ url: 'https://github.com/acme/no-auth' });
    expect(res.status).toBe(401);
  });
});

// ── GET /api/scan/fetchRepos ─────────────────────────────────────────────────
describe('Scan – GET /api/scan/fetchRepos', () => {
  it('returns only the authenticated user\'s repos', async () => {
    const t1 = await getToken();
    const t2 = await getToken();

    await request(app).post('/api/scan/addRepo')
      .set('Authorization', `Bearer ${t1}`)
      .send({ url: 'https://github.com/user1/repo-a' });
    await request(app).post('/api/scan/addRepo')
      .set('Authorization', `Bearer ${t2}`)
      .send({ url: 'https://github.com/user2/repo-b' });

    const res = await request(app).get('/api/scan/fetchRepos')
      .set('Authorization', `Bearer ${t1}`);
    expect(res.status).toBe(200);
    expect(res.body.items).toHaveLength(1);
    expect(res.body.items[0].name).toBe('user1/repo-a');
  });

  it('returns 401 without a token', async () => {
    const res = await request(app).get('/api/scan/fetchRepos');
    expect(res.status).toBe(401);
  });
});

// ── POST /api/scan/refreshRepo/:repoId ──────────────────────────────────────
describe('Scan – POST /api/scan/refreshRepo/:repoId', () => {
  it('queues a refresh and returns 202', async () => {
    const token = await getToken();
    const add = await request(app).post('/api/scan/addRepo')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://github.com/acme/refresh-repo' });

    // Wait briefly for the mock worker to mark it idle
    await new Promise((r) => setTimeout(r, 50));

    const { Repo } = require('../../src/models');
    await Repo.findByIdAndUpdate(add.body.repo._id, { status: 'idle' });

    const res = await request(app).post(`/api/scan/refreshRepo/${add.body.repo._id}`)
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(202);
    expect(res.body.message).toMatch(/background/i);
    expect(res.body.scan.status).toBe('queued');
  });

  it('returns 409 when a scan is already in progress', async () => {
    const { dispatchScanJob } = require('../../src/worker/index');
    dispatchScanJob.mockImplementationOnce(() => ({ on: jest.fn(), send: jest.fn(), unref: jest.fn() }));

    const token = await getToken();
    const add = await request(app).post('/api/scan/addRepo')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://github.com/acme/busy-repo' });

    // Keep it in 'scanning' state (mockImplementationOnce skips auto-completing)
    const res = await request(app).post(`/api/scan/refreshRepo/${add.body.repo._id}`)
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('SCAN_IN_PROGRESS');
  });

  it('returns 404 for a repo belonging to another user', async () => {
    const t1 = await getToken();
    const t2 = await getToken();
    const add = await request(app).post('/api/scan/addRepo')
      .set('Authorization', `Bearer ${t1}`)
      .send({ url: 'https://github.com/user1/secret-repo' });

    const res = await request(app).post(`/api/scan/refreshRepo/${add.body.repo._id}`)
      .set('Authorization', `Bearer ${t2}`);
    expect(res.status).toBe(404);
  });
});
