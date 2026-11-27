// API tests: GET /api/cve/:cveId and the CVE enrichment of GET /api/vulnerability/:findingId.
const fs = require('node:fs');
const path = require('node:path');
const mongoose = require('mongoose');
const request = require('supertest');
const app = require('../../src/app');
const ApiError = require('../../src/utils/ApiError');
const { Component, CveCache, Finding } = require('../../src/models');
const { createCveLookup } = require('../../src/services/cve');
const { useDatabase, makeUser, seedRepo, stubCveLookup } = require('./helpers');

useDatabase();

const log4j = fs.readFileSync(path.join(__dirname, 'fixtures', 'CVE-2021-44228.json'), 'utf8');

const bracesCve = {
  cveId: 'CVE-2024-4068', state: 'PUBLISHED', score: 7.5, severity: 'high', cvssVersion: '3.1',
  vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', source: 'Checkmarx',
  description: 'The NPM package braces fails to limit the number of characters it can handle',
  cwes: ['CWE-1050', 'CWE-400'], url: 'https://www.cve.org/CVERecord?id=CVE-2024-4068',
};

afterEach(() => {
  delete app.locals.cveLookup;
  delete app.locals.cveRateLimit;
});

describe('GET /api/cve/:cveId', () => {
  test('needs a token', async () => {
    const res = await request(app).get('/api/cve/CVE-2021-44228');
    expect(res.status).toBe(401);
  });

  test('returns the score and caches it in MongoDB', async () => {
    const fetchImpl = jest.fn(async () => new Response(log4j, { status: 200 }));
    app.locals.cveLookup = createCveLookup({ fetchImpl }); // real lookup + real Mongo cache, fake network
    const { auth } = await makeUser();

    const first = await request(app).get('/api/cve/CVE-2021-44228').set(auth);
    expect(first.status).toBe(200);
    expect(first.body).toMatchObject({ cveId: 'CVE-2021-44228', score: 10, severity: 'critical', cached: false });

    const second = await request(app).get('/api/cve/cve-2021-44228').set(auth);
    expect(second.body.cached).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const doc = await CveCache.findOne({ cveId: 'CVE-2021-44228' }).lean();
    expect(doc.found).toBe(true);
    expect(doc.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  test('404 for CVEs that do not exist', async () => {
    app.locals.cveLookup = stubCveLookup({});
    const { auth } = await makeUser();
    const res = await request(app).get('/api/cve/CVE-2099-99999').set(auth);
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('502 with a safe message when cvelistV5 is down', async () => {
    app.locals.cveLookup = createCveLookup({
      fetchImpl: async () => { throw new TypeError('getaddrinfo ENOTFOUND raw.githubusercontent.com'); },
    });
    const { auth } = await makeUser();
    const res = await request(app).get('/api/cve/CVE-2021-44228').set(auth);
    expect(res.status).toBe(502);
    expect(res.body).toEqual({ error: { code: 'UPSTREAM_UNAVAILABLE', message: 'CVE database is unavailable, try again later' } });
  });

  test.each(['CVE-21-1', 'not-a-cve', 'CVE-2021-44228..%2F..%2Fx'])('rejects %s without a lookup', async (id) => {
    const stub = stubCveLookup({});
    app.locals.cveLookup = stub;
    const { auth } = await makeUser();
    const res = await request(app).get(`/api/cve/${id}`).set(auth);
    expect(res.status).toBe(400);
    expect(stub.calls).toHaveLength(0);
  });

  test('rate-limits each user separately', async () => {
    app.locals.cveLookup = stubCveLookup({ 'CVE-2024-4068': bracesCve });
    app.locals.cveRateLimit = 3;
    const a = await makeUser();
    const b = await makeUser();
    for (let i = 0; i < 3; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      expect((await request(app).get('/api/cve/CVE-2024-4068').set(a.auth)).status).toBe(200);
    }
    const limited = await request(app).get('/api/cve/CVE-2024-4068').set(a.auth);
    expect(limited.status).toBe(429);
    expect(limited.body.error.code).toBe('RATE_LIMITED');
    expect((await request(app).get('/api/cve/CVE-2024-4068').set(b.auth)).status).toBe(200);
  });
});

describe('GET /api/vulnerability/:findingId with the fallback lookup', () => {
  const findingOf = (seed, vulnId) => seed.findings.find((f) => f.vulnId === vulnId);

  test('fills a missing score from cvelistV5, saves it and updates the SBOM row', async () => {
    const { user, auth } = await makeUser();
    const seed = await seedRepo(user);
    app.locals.cveLookup = stubCveLookup({ 'CVE-2024-4068': bracesCve });
    const braces = findingOf(seed, 'GHSA-grv7-fg5c-xmjg');

    const res = await request(app).get(`/api/vulnerability/${braces._id}`).set(auth);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      score: 7.5, severity: 'high', scoreSource: 'cvelistV5',
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      cwes: ['CWE-1050', 'CWE-400'],
    });
    expect(res.body.scoring.explanation).toBe(
      'Score 7.5 (CVSS 3.1) taken from the CVE record in cvelistV5 (fallback lookup); severity band high = 7.0-8.9',
    );
    expect(res.body.cves).toEqual([expect.objectContaining({ cveId: 'CVE-2024-4068', source: 'Checkmarx', score: 7.5 })]);

    const saved = await Finding.findById(braces._id).lean();
    expect(saved).toMatchObject({ score: 7.5, severity: 'high', scoreSource: 'cvelistV5' });
    const comp = await Component.findOne({ repo: seed.repo._id, name: 'braces' }).lean();
    expect(comp).toMatchObject({ maxSeverity: 'high', vulnerabilityCount: 1 });

    // the list endpoint now counts it as high
    const list = await request(app).get(`/api/vulnerability/filter/${seed.repo._id}`).set(auth);
    expect(list.body.counts).toMatchObject({ high: 2, unknown: 0 });
  });

  test('keeps the OSV score when there is one, but still adds the CVE details', async () => {
    const { user, auth } = await makeUser();
    const seed = await seedRepo(user);
    app.locals.cveLookup = stubCveLookup({ 'CVE-2022-24999': { ...bracesCve, cveId: 'CVE-2022-24999', score: 9.9, source: 'CISA-ADP' } });
    const qsFinding = findingOf(seed, 'GHSA-hrpp-h998-j3pp');
    const res = await request(app).get(`/api/vulnerability/${qsFinding._id}`).set(auth);
    expect(res.body).toMatchObject({ score: 7.5, scoreSource: 'osv' });
    expect(res.body.cves[0]).toMatchObject({ cveId: 'CVE-2022-24999', source: 'CISA-ADP' });
  });

  test('does not look up again once enriched', async () => {
    const { user, auth } = await makeUser();
    const seed = await seedRepo(user);
    const stub = stubCveLookup({ 'CVE-2024-4068': bracesCve });
    app.locals.cveLookup = stub;
    const id = findingOf(seed, 'GHSA-grv7-fg5c-xmjg')._id;
    await request(app).get(`/api/vulnerability/${id}`).set(auth);
    await request(app).get(`/api/vulnerability/${id}`).set(auth);
    expect(stub.calls).toEqual(['CVE-2024-4068']);
  });

  test('still answers when cvelistV5 is down, and retries next time', async () => {
    const { user, auth } = await makeUser();
    const seed = await seedRepo(user);
    const id = findingOf(seed, 'GHSA-grv7-fg5c-xmjg')._id;
    app.locals.cveLookup = stubCveLookup({ 'CVE-2024-4068': new ApiError(502, 'UPSTREAM_UNAVAILABLE', 'down') });

    const res = await request(app).get(`/api/vulnerability/${id}`).set(auth);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ score: null, severity: 'unknown' });
    expect(res.body.cves).toEqual([{ cveId: 'CVE-2024-4068', error: 'UPSTREAM_UNAVAILABLE' }]);

    app.locals.cveLookup = stubCveLookup({ 'CVE-2024-4068': bracesCve });
    const retry = await request(app).get(`/api/vulnerability/${id}`).set(auth);
    expect(retry.body).toMatchObject({ score: 7.5, scoreSource: 'cvelistV5' });
  });

  test("another user's finding stays hidden (no lookup either)", async () => {
    const owner = await makeUser();
    const other = await makeUser();
    const seed = await seedRepo(owner.user);
    const stub = stubCveLookup({ 'CVE-2024-4068': bracesCve });
    app.locals.cveLookup = stub;
    const res = await request(app).get(`/api/vulnerability/${findingOf(seed, 'GHSA-grv7-fg5c-xmjg')._id}`).set(other.auth);
    expect(res.status).toBe(404);
    expect(stub.calls).toHaveLength(0);
  });

  test('a random id is a plain 404', async () => {
    const { auth } = await makeUser();
    const res = await request(app).get(`/api/vulnerability/${new mongoose.Types.ObjectId()}`).set(auth);
    expect(res.status).toBe(404);
  });
});
