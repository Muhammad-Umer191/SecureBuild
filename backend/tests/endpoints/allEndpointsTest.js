// tests/endpoints/allEndpointsTest.js
// End-to-end test suite for all SecureBuild API endpoints + service integration.
// Covers both positive flows (2xx) and negative/invalid inputs (4xx) and prints
// each endpoint's returned status and JSON response.

const path = require('path');
const fs = require('fs/promises');
const os = require('os');
const request = require('supertest');
const app = require('../../src/app');
const { Repo, Scan, Finding, Component } = require('../../src/models');
const scannerService = require('../../src/services/scannerService');
const { createMemoryCache } = require('../../src/services/osv');
const { fakeOsvClient, SHA } = require('../services/scan/fakes');

// Mock only the child_process fork dispatcher in HTTP tests so tests stay fast
// and deterministic; we also test the real scannerService pipeline directly below.
jest.mock('../../src/worker/index', () => ({
  dispatchScanJob: jest.fn((payload) => {
    setImmediate(async () => {
      const { Repo, Scan } = require('../../src/models');
      try {
        const scan = await Scan.findById(payload.scanId);
        const repo = await Repo.findById(payload.repoId);
        if (scan) {
          scan.status = 'completed';
          scan.commitSha = 'abc123def456';
          scan.finishedAt = new Date();
          await scan.save();
        }
        if (repo) {
          repo.status = 'idle';
          repo.lastScan = payload.scanId;
          await repo.save();
        }
      } catch (_) {
        // ignore in test cleanup
      }
    });
    return { on: jest.fn(), send: jest.fn(), unref: jest.fn() };
  }),
}));

function logResult(label, res) {
  const preview = JSON.stringify(res.body, null, 2);
  process.stdout.write(`\n[${label}] HTTP ${res.status}\n${preview}\n`);
}

let tempDirs = [];
afterEach(async () => {
  for (const d of tempDirs) {
    await fs.rm(d, { recursive: true, force: true }).catch(() => {});
  }
  tempDirs = [];
});

async function makeTempRepo(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sb-e2e-'));
  tempDirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content, 'utf8');
  }
  return dir;
}

describe('SecureBuild End-to-End API & Service Integration', () => {
  // ── 1. Health ───────────────────────────────────────────────────────────────
  describe('GET /api/health', () => {
    it('returns 200 ok', async () => {
      const res = await request(app).get('/api/health');
      logResult('GET /api/health (valid)', res);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: 'ok' });
    });
  });

  // ── 2. Auth Endpoints ───────────────────────────────────────────────────────
  describe('Auth Endpoints (/api/auth/*)', () => {
    it('POST /api/auth/register -> 201 on valid input', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Umer', email: 'umer@securebuild.dev', password: 'Password1!' });
      logResult('POST /api/auth/register (valid)', res);
      expect(res.status).toBe(201);
      expect(res.body.token).toBeDefined();
      expect(res.body.user.email).toBe('umer@securebuild.dev');
    });

    it('POST /api/auth/register -> 409 on duplicate email', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({ name: 'Umer', email: 'dup@securebuild.dev', password: 'Password1!' });
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Umer 2', email: 'dup@securebuild.dev', password: 'Password1!' });
      logResult('POST /api/auth/register (duplicate email)', res);
      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('DUPLICATE');
    });

    it('POST /api/auth/register -> 400 on short password and invalid email', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Bad', email: 'not-an-email', password: '123' });
      logResult('POST /api/auth/register (invalid values)', res);
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('POST /api/auth/login -> 200 on valid credentials', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({ name: 'Login User', email: 'login@securebuild.dev', password: 'Password1!' });
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'login@securebuild.dev', password: 'Password1!' });
      logResult('POST /api/auth/login (valid)', res);
      expect(res.status).toBe(200);
      expect(res.body.token).toBeDefined();
    });

    it('POST /api/auth/login -> 401 on wrong password', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({ name: 'Login User', email: 'wrongpw@securebuild.dev', password: 'Password1!' });
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'wrongpw@securebuild.dev', password: 'WrongPassword!' });
      logResult('POST /api/auth/login (wrong password)', res);
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('AUTH_INVALID');
    });

    it('GET /api/auth/me -> 200 with token, 401 without or invalid token', async () => {
      const reg = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Me User', email: 'me@securebuild.dev', password: 'Password1!' });

      const okRes = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${reg.body.token}`);
      logResult('GET /api/auth/me (valid token)', okRes);
      expect(okRes.status).toBe(200);
      expect(okRes.body.user.email).toBe('me@securebuild.dev');

      const noTok = await request(app).get('/api/auth/me');
      logResult('GET /api/auth/me (missing token)', noTok);
      expect(noTok.status).toBe(401);

      const badTok = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalid.jwt.token');
      logResult('GET /api/auth/me (invalid token)', badTok);
      expect(badTok.status).toBe(401);
    });

    it('POST /api/auth/changePassword -> 200 valid, 401 wrong current, 400 same password', async () => {
      const reg = await request(app)
        .post('/api/auth/register')
        .send({ name: 'PW User', email: 'pw@securebuild.dev', password: 'Password1!' });
      const token = reg.body.token;

      const badCurr = await request(app)
        .post('/api/auth/changePassword')
        .set('Authorization', `Bearer ${token}`)
        .send({ currentPassword: 'WrongCurrent!', newPassword: 'NewPassword2!' });
      logResult('POST /api/auth/changePassword (wrong currentPassword)', badCurr);
      expect(badCurr.status).toBe(401);

      const samePw = await request(app)
        .post('/api/auth/changePassword')
        .set('Authorization', `Bearer ${token}`)
        .send({ currentPassword: 'Password1!', newPassword: 'Password1!' });
      logResult('POST /api/auth/changePassword (same newPassword)', samePw);
      expect(samePw.status).toBe(400);

      const ok = await request(app)
        .post('/api/auth/changePassword')
        .set('Authorization', `Bearer ${token}`)
        .send({ currentPassword: 'Password1!', newPassword: 'NewPassword2!' });
      logResult('POST /api/auth/changePassword (valid)', ok);
      expect(ok.status).toBe(200);
    });
  });

  // ── 3. Scan Endpoints ───────────────────────────────────────────────────────
  describe('Scan Endpoints (/api/scan/*)', () => {
    async function createAuthedUser(suffix) {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: `User ${suffix}`, email: `scan_${suffix}@securebuild.dev`, password: 'Password1!' });
      return res.body.token;
    }

    it('POST /api/scan/addRepo -> 201 valid, 400 non-GitHub URL, 409 duplicate, 401 no token', async () => {
      const token = await createAuthedUser('add');

      const noAuth = await request(app)
        .post('/api/scan/addRepo')
        .send({ url: 'https://github.com/acme/demo' });
      logResult('POST /api/scan/addRepo (no token)', noAuth);
      expect(noAuth.status).toBe(401);

      const badUrl = await request(app)
        .post('/api/scan/addRepo')
        .set('Authorization', `Bearer ${token}`)
        .send({ url: 'https://gitlab.com/acme/demo' });
      logResult('POST /api/scan/addRepo (non-GitHub URL)', badUrl);
      expect(badUrl.status).toBe(400);
      expect(badUrl.body.error.code).toBe('VALIDATION_ERROR');

      const ok = await request(app)
        .post('/api/scan/addRepo')
        .set('Authorization', `Bearer ${token}`)
        .send({ url: 'https://github.com/acme/demo' });
      logResult('POST /api/scan/addRepo (valid)', ok);
      expect(ok.status).toBe(201);
      expect(ok.body.repo.name).toBe('acme/demo');

      const dup = await request(app)
        .post('/api/scan/addRepo')
        .set('Authorization', `Bearer ${token}`)
        .send({ url: 'https://github.com/acme/demo' });
      logResult('POST /api/scan/addRepo (duplicate)', dup);
      expect(dup.status).toBe(409);
      expect(dup.body.error.code).toBe('DUPLICATE');
    });

    it('GET /api/scan/fetchRepos -> 200 user repos, 401 no token', async () => {
      const t1 = await createAuthedUser('fetch1');
      const t2 = await createAuthedUser('fetch2');

      await request(app)
        .post('/api/scan/addRepo')
        .set('Authorization', `Bearer ${t1}`)
        .send({ url: 'https://github.com/owner1/app1' });

      const noAuth = await request(app).get('/api/scan/fetchRepos');
      logResult('GET /api/scan/fetchRepos (no token)', noAuth);
      expect(noAuth.status).toBe(401);

      const res1 = await request(app)
        .get('/api/scan/fetchRepos')
        .set('Authorization', `Bearer ${t1}`);
      logResult('GET /api/scan/fetchRepos (owner 1)', res1);
      expect(res1.status).toBe(200);
      expect(res1.body.items).toHaveLength(1);

      const res2 = await request(app)
        .get('/api/scan/fetchRepos')
        .set('Authorization', `Bearer ${t2}`);
      logResult('GET /api/scan/fetchRepos (owner 2 - empty)', res2);
      expect(res2.status).toBe(200);
      expect(res2.body.items).toHaveLength(0);
    });

    it('POST /api/scan/refreshRepo/:repoId -> 202 valid, 409 busy, 404 other user, 400 bad id', async () => {
      const { dispatchScanJob } = require('../../src/worker/index');
      const t1 = await createAuthedUser('ref1');
      const t2 = await createAuthedUser('ref2');

      dispatchScanJob.mockImplementationOnce(() => ({ on: jest.fn(), send: jest.fn(), unref: jest.fn() }));
      const add = await request(app)
        .post('/api/scan/addRepo')
        .set('Authorization', `Bearer ${t1}`)
        .send({ url: 'https://github.com/acme/refresh-target' });
      const repoId = add.body.repo._id;

      // Immediately while status === 'scanning' -> 409
      const busy = await request(app)
        .post(`/api/scan/refreshRepo/${repoId}`)
        .set('Authorization', `Bearer ${t1}`);
      logResult('POST /api/scan/refreshRepo/:repoId (scan in progress)', busy);
      expect(busy.status).toBe(409);

      // Mark idle -> 202
      await new Promise((r) => setTimeout(r, 50));
      await Repo.findByIdAndUpdate(repoId, { status: 'idle' });

      const ok = await request(app)
        .post(`/api/scan/refreshRepo/${repoId}`)
        .set('Authorization', `Bearer ${t1}`);
      logResult('POST /api/scan/refreshRepo/:repoId (valid)', ok);
      expect(ok.status).toBe(202);
      expect(ok.body.scan.status).toBe('queued');

      const otherUser = await request(app)
        .post(`/api/scan/refreshRepo/${repoId}`)
        .set('Authorization', `Bearer ${t2}`);
      logResult('POST /api/scan/refreshRepo/:repoId (another user)', otherUser);
      expect(otherUser.status).toBe(404);

      const badId = await request(app)
        .post('/api/scan/refreshRepo/invalid-id')
        .set('Authorization', `Bearer ${t1}`);
      logResult('POST /api/scan/refreshRepo/:repoId (invalid id)', badId);
      expect(badId.status).toBe(400);
    });
  });

  // ── 4. Real Scanner Service -> Vulnerability Endpoints Integration ──────────
  describe('Service Integration + Vulnerability Endpoints (/api/vulnerability/*)', () => {
    it('scans a repo WITH vulnerabilities via scannerService and exposes them on /show, /filter, /:id, PATCH /:id', async () => {
      const reg = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Scanner', email: 'vuln_flow@securebuild.dev', password: 'Password1!' });
      const token = reg.body.token;
      const userId = reg.body.user.id;

      const repo = await Repo.create({
        owner: userId,
        url: 'https://github.com/acme/vuln-app',
        name: 'acme/vuln-app',
        status: 'idle',
      });
      const scan = await Scan.create({ repo: repo._id, status: 'running', startedAt: new Date() });

      // Run the real scannerService pipeline against the fixture repo (contains lodash@4.17.21)
      const fixtureDir = await makeTempRepo({
        'package.json': JSON.stringify({ name: 'vuln-app', version: '1.0.0', dependencies: { lodash: '^4.17.21' } }),
        'package-lock.json': JSON.stringify({
          name: 'vuln-app',
          version: '1.0.0',
          lockfileVersion: 3,
          packages: {
            '': { name: 'vuln-app', version: '1.0.0', dependencies: { lodash: '^4.17.21' } },
            'node_modules/lodash': { version: '4.17.21', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz' },
          },
        }),
      });

      const scanOutput = await scannerService.scanRepository(repo.url, {
        withClone: async (_url, fn) => fn({ dir: fixtureDir, commitSha: SHA }),
        osvClient: fakeOsvClient([]),
        cache: createMemoryCache(),
      });

      expect(scanOutput.findings.length).toBeGreaterThan(0);

      // Persist findings & components just as scanWorker does
      const savedFindings = [];
      for (const f of scanOutput.findings) {
        const doc = await Finding.create({ ...f, repo: repo._id, scan: scan._id, status: 'open' });
        savedFindings.push(doc);
      }
      await Component.insertMany(scanOutput.components.map((c) => ({ ...c, repo: repo._id, scan: scan._id })));
      scan.status = 'completed';
      scan.commitSha = scanOutput.commitSha;
      scan.finishedAt = new Date();
      scan.findingsCount = savedFindings.length;
      scan.componentsCount = scanOutput.components.length;
      await scan.save();
      repo.lastScan = scan._id;
      await repo.save();

      // GET /api/vulnerability/show/:repoId
      const showRes = await request(app)
        .get(`/api/vulnerability/show/${repo._id}`)
        .set('Authorization', `Bearer ${token}`);
      logResult('GET /api/vulnerability/show/:repoId (with findings)', showRes);
      expect(showRes.status).toBe(200);
      expect(showRes.body.total).toBe(savedFindings.length);
      expect(showRes.body.items[0].package.name).toBe('lodash');
      expect(showRes.body.items[0].package.version).toBe('4.17.21');
      expect(showRes.body.items[0].package.ecosystem).toBe('npm');
      expect(showRes.body.items[0].direct).toBe(true);

      // GET /api/vulnerability/filter/:repoId (positive filter)
      const filterHigh = await request(app)
        .get(`/api/vulnerability/filter/${repo._id}?severity=high&status=open`)
        .set('Authorization', `Bearer ${token}`);
      logResult('GET /api/vulnerability/filter/:repoId (severity=high)', filterHigh);
      expect(filterHigh.status).toBe(200);
      expect(filterHigh.body.items.length).toBeGreaterThan(0);

      // GET /api/vulnerability/filter/:repoId (negative invalid status)
      const filterBad = await request(app)
        .get(`/api/vulnerability/filter/${repo._id}?status=bogus`)
        .set('Authorization', `Bearer ${token}`);
      logResult('GET /api/vulnerability/filter/:repoId (invalid status)', filterBad);
      expect(filterBad.status).toBe(400);

      // GET /api/vulnerability/:findingId
      const findingId = savedFindings[0]._id;
      const singleRes = await request(app)
        .get(`/api/vulnerability/${findingId}`)
        .set('Authorization', `Bearer ${token}`);
      logResult('GET /api/vulnerability/:findingId (valid)', singleRes);
      expect(singleRes.status).toBe(200);
      expect(singleRes.body.vulnId).toBe(savedFindings[0].vulnId);

      // GET /api/vulnerability/:findingId (negative malformed id)
      const badFindingId = await request(app)
        .get('/api/vulnerability/not-an-object-id')
        .set('Authorization', `Bearer ${token}`);
      logResult('GET /api/vulnerability/:findingId (malformed id)', badFindingId);
      expect(badFindingId.status).toBe(400);

      // PATCH /api/vulnerability/:findingId (negative: missing reason)
      const patchMissingReason = await request(app)
        .patch(`/api/vulnerability/${findingId}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ status: 'ignored' });
      logResult('PATCH /api/vulnerability/:findingId (missing reason)', patchMissingReason);
      expect(patchMissingReason.status).toBe(400);

      // PATCH /api/vulnerability/:findingId (valid ignore)
      const patchIgnore = await request(app)
        .patch(`/api/vulnerability/${findingId}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ status: 'ignored', reason: 'Accepted risk for sprint' });
      logResult('PATCH /api/vulnerability/:findingId (ignore valid)', patchIgnore);
      expect(patchIgnore.status).toBe(200);
      expect(patchIgnore.body.status).toBe('ignored');

      // PATCH /api/vulnerability/:findingId (valid reopen)
      const patchReopen = await request(app)
        .patch(`/api/vulnerability/${findingId}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ status: 'open' });
      logResult('PATCH /api/vulnerability/:findingId (reopen valid)', patchReopen);
      expect(patchReopen.status).toBe(200);
      expect(patchReopen.body.status).toBe('open');
    });

    it('scans a CLEAN repo (no vulnerabilities) and returns 0 vulnerabilities', async () => {
      const reg = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Clean Scanner', email: 'clean_flow@securebuild.dev', password: 'Password1!' });
      const token = reg.body.token;
      const userId = reg.body.user.id;

      const repo = await Repo.create({
        owner: userId,
        url: 'https://github.com/acme/clean-app',
        name: 'acme/clean-app',
        status: 'idle',
      });
      const scan = await Scan.create({ repo: repo._id, status: 'running', startedAt: new Date() });

      const cleanDir = await makeTempRepo({
        'README.md': '# Clean Repo\nNo dependencies here.',
      });

      const scanOutput = await scannerService.scanRepository(repo.url, {
        withClone: async (_url, fn) => fn({ dir: cleanDir, commitSha: SHA }),
        osvClient: fakeOsvClient([]),
        cache: createMemoryCache(),
      });

      expect(scanOutput.findings).toEqual([]);
      scan.status = 'completed';
      scan.commitSha = scanOutput.commitSha;
      scan.finishedAt = new Date();
      scan.findingsCount = 0;
      scan.componentsCount = 0;
      await scan.save();
      repo.lastScan = scan._id;
      await repo.save();

      const showClean = await request(app)
        .get(`/api/vulnerability/show/${repo._id}`)
        .set('Authorization', `Bearer ${token}`);
      logResult('GET /api/vulnerability/show/:repoId (clean repo, 0 vulns)', showClean);
      expect(showClean.status).toBe(200);
      expect(showClean.body.items).toEqual([]);
      expect(showClean.body.total).toBe(0);
    });
  });
});
