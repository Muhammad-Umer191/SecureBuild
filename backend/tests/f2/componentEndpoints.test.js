// API tests: GET /api/component/show/:repoId (SBOM tab) and /api/component/export/:repoId (CycloneDX).
const mongoose = require('mongoose');
const request = require('supertest');
const app = require('../../src/app');
const { Finding, Repo, Scan } = require('../../src/models');
const { buildSbom, sbomFileName } = require('../../src/services/sbomExport');
const { validateBom } = require('../services/cyclonedx/validateBom');
const { useDatabase, makeUser, seedRepo, COMPONENTS, FINDINGS } = require('./helpers');

useDatabase();

describe('GET /api/component/show/:repoId', () => {
  test('lists components with whole-repo totals', async () => {
    const { user, auth } = await makeUser();
    const seed = await seedRepo(user);
    const res = await request(app).get(`/api/component/show/${seed.repo._id}`).set(auth);
    expect(res.status).toBe(200);
    expect(res.body.total).toBe(COMPONENTS.length);
    expect(res.body.scan).toMatchObject({ commitSha: 'a1b2c3d4e5f6' });
    expect(res.body.summary).toEqual({
      total: 7, direct: 4, transitive: 3, vulnerable: 4, byEcosystem: { npm: 5, PyPI: 2 },
    });
    expect(res.body.items[0]).toEqual({
      id: expect.any(String), name: '@babel/core', version: '7.22.0', ecosystem: 'npm',
      purl: 'pkg:npm/%40babel/core@7.22.0', direct: true, licenses: ['MIT'], vulnerabilityCount: 0, maxSeverity: null,
    });
  });

  test('filters, sorts and pages; the summary stays whole-repo', async () => {
    const { user, auth } = await makeUser();
    const seed = await seedRepo(user);
    const get = (qs) => request(app).get(`/api/component/show/${seed.repo._id}?${qs}`).set(auth);

    let res = await get('vulnerable=true&sort=vulns&order=desc');
    expect(res.body.total).toBe(4);
    expect(res.body.items.every((c) => c.vulnerabilityCount > 0)).toBe(true);
    expect(res.body.summary.total).toBe(7);

    res = await get('ecosystem=PyPI&direct=false');
    expect(res.body.items.map((c) => c.name)).toEqual(['urllib3']);

    res = await get('q=pkg%3Anpm%2Fl');
    expect(res.body.items.map((c) => c.name)).toEqual(['lodash']);

    res = await get(`q=${encodeURIComponent('.*')}`);
    expect(res.body.total).toBe(0); // regex characters are plain text

    res = await get('limit=3&page=3');
    expect(res.body).toMatchObject({ page: 3, limit: 3 });
    expect(res.body.items).toHaveLength(1);
  });

  test.each([
    'limit=201', 'ecosystem=maven', 'vulnerable=1', 'sort=-name', 'page=0', 'name[$regex]=.*', 'ecosystem[$ne]=npm',
  ])('rejects or ignores bad query %s safely', async (qs) => {
    const { user, auth } = await makeUser();
    const seed = await seedRepo(user);
    const res = await request(app).get(`/api/component/show/${seed.repo._id}?${qs}`).set(auth);
    if (res.status === 200) {
      // unknown keys are stripped by the validator: the full, unfiltered list comes back
      expect(res.body.total).toBe(7);
    } else {
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    }
  });

  test("another user's repo is a generic 404", async () => {
    const owner = await makeUser();
    const other = await makeUser();
    const seed = await seedRepo(owner.user);
    const res = await request(app).get(`/api/component/show/${seed.repo._id}`).set(other.auth);
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: { code: 'NOT_FOUND', message: 'Repository not found' } });
  });

  test('needs a token and a valid id', async () => {
    const { auth } = await makeUser();
    expect((await request(app).get(`/api/component/show/${new mongoose.Types.ObjectId()}`)).status).toBe(401);
    expect((await request(app).get('/api/component/show/not-an-id').set(auth)).status).toBe(400);
  });
});

describe('GET /api/component/export/:repoId', () => {
  test('downloads a schema-valid CycloneDX 1.5 SBOM', async () => {
    const { user, auth } = await makeUser();
    const seed = await seedRepo(user);
    const res = await request(app).get(`/api/component/export/${seed.repo._id}?format=cyclonedx`).set(auth);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/vnd\.cyclonedx\+json/);
    expect(res.headers['content-disposition']).toBe('attachment; filename="acme-shop-api-sbom.cdx.json"');
    expect(res.headers['cache-control']).toBe('no-store');

    const bom = JSON.parse(res.text);
    expect(validateBom(bom)).toEqual([]);
    expect(bom).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.5' });
    expect(bom.metadata.component).toMatchObject({ name: 'acme/shop-api', version: 'a1b2c3d4e5f6' });
    expect(bom.components).toHaveLength(COMPONENTS.length);
    expect(bom.vulnerabilities).toHaveLength(FINDINGS.length);
    // only the dependency link we really know: repo -> direct packages
    expect(bom.dependencies).toEqual([{
      ref: 'https://github.com/acme/shop-api',
      dependsOn: expect.arrayContaining(['pkg:npm/lodash@4.17.11', 'pkg:pypi/requests@2.25.1']),
    }]);
    const lodash = bom.vulnerabilities.find((v) => v.id === 'GHSA-jf85-cpcp-j695');
    expect(lodash.ratings[0]).toMatchObject({ score: 9.1, severity: 'critical', method: 'CVSSv31' });
    expect(lodash.references).toEqual([expect.objectContaining({ id: 'CVE-2019-10744' })]);
    expect(res.text).not.toContain(String(user._id)); // sanitised
  });

  test('leaves ignored findings (and their reasons) out', async () => {
    const { user, auth } = await makeUser();
    const seed = await seedRepo(user);
    const lodash = seed.findings.find((f) => f.vulnId === 'GHSA-jf85-cpcp-j695');
    await request(app).patch(`/api/vulnerability/${lodash._id}`).set(auth)
      .send({ status: 'ignored', reason: 'Accepted risk for the demo' })
      .expect(200);
    const res = await request(app).get(`/api/component/export/${seed.repo._id}`).set(auth);
    const bom = JSON.parse(res.text);
    expect(bom.vulnerabilities.map((v) => v.id)).not.toContain('GHSA-jf85-cpcp-j695');
    expect(res.text).not.toContain('Accepted risk');
  });

  test('says NO_SCAN before the first scan finishes', async () => {
    const { user, auth } = await makeUser();
    const repo = await Repo.create({ owner: user._id, url: 'https://github.com/acme/new', name: 'acme/new' });
    await Scan.create({ repo: repo._id, status: 'running' });
    const res = await request(app).get(`/api/component/export/${repo._id}`).set(auth);
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NO_SCAN');
  });

  test('rejects other formats', async () => {
    const { user, auth } = await makeUser();
    const seed = await seedRepo(user);
    const res = await request(app).get(`/api/component/export/${seed.repo._id}?format=spdx`).set(auth);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/cyclonedx/);
  });

  test("another user's repo is a 404", async () => {
    const owner = await makeUser();
    const other = await makeUser();
    const seed = await seedRepo(owner.user);
    expect((await request(app).get(`/api/component/export/${seed.repo._id}`).set(other.auth)).status).toBe(404);
  });
});

describe('sbomExport helpers', () => {
  test('safe download names', () => {
    expect(sbomFileName({ name: 'acme/shop-api' })).toBe('acme-shop-api-sbom.cdx.json');
    expect(sbomFileName({ name: 'a/b"\r\nX-Evil: 1' })).toBe('a-b___X-Evil__1-sbom.cdx.json');
  });

  test('a finding with only a severity label (no score) is still exported validly', () => {
    const bom = buildSbom({
      repo: { url: 'https://github.com/a/b', name: 'a/b' },
      scan: null,
      components: [{ name: 'x', version: '1.0.0', ecosystem: 'npm', purl: 'pkg:npm/x@1.0.0', direct: true, licenses: [] }],
      findings: [{
        vulnId: 'GHSA-aaaa-bbbb-cccc', aliases: [], cveIds: [], summary: 'x', severity: 'high', score: null,
        status: 'open', package: { purl: 'pkg:npm/x@1.0.0' }, references: [],
      }],
    });
    expect(validateBom(bom)).toEqual([]);
    expect(bom.vulnerabilities[0].ratings[0]).toMatchObject({ severity: 'high', method: 'other' });
    expect(bom.metadata.component).not.toHaveProperty('version');
  });

  test('findings for packages missing from the SBOM are skipped instead of crashing', async () => {
    const bom = buildSbom({
      repo: { url: 'https://github.com/a/b', name: 'a/b' },
      scan: null,
      components: [],
      findings: [await new Finding({
        repo: new mongoose.Types.ObjectId(), scan: new mongoose.Types.ObjectId(), vulnId: 'GHSA-x', summary: 's',
        package: { name: 'gone', version: '1', ecosystem: 'npm', purl: 'pkg:npm/gone@1' },
      }).toObject()],
    });
    expect(bom.vulnerabilities).toEqual([]);
  });
});
