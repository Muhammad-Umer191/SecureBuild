// Shared setup for the F2 tests: in-memory MongoDB, a signed-in user, sample scan data.
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const config = require('../../src/config');
const { User, Repo, Scan, Finding, Component } = require('../../src/models');

/**
 * Makes sure the test file has an in-memory MongoDB and empties it after each test.
 * tests/setup.js (jest setupFilesAfterEnv) normally connects first; then that connection
 * is reused. Only when nothing is connected (e.g. run without the jest config) is a
 * database started here, and only that one is stopped afterwards.
 */
function useDatabase() {
  let mongod = null;
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      mongod = await MongoMemoryServer.create();
      await mongoose.connect(mongod.getUri());
    }
    await Promise.all(Object.values(mongoose.models).map((m) => m.syncIndexes()));
  }, 120000);
  afterEach(async () => {
    await Promise.all(Object.values(mongoose.connection.collections).map((c) => c.deleteMany({})));
  });
  afterAll(async () => {
    if (mongod) {
      await mongoose.disconnect();
      await mongod.stop();
    }
  });
}

let userSeq = 0;
async function makeUser() {
  userSeq += 1;
  const user = await User.create({ email: `user${userSeq}@example.test`, password: 'password123', name: `User ${userSeq}` });
  const token = jwt.sign({ sub: String(user._id) }, config.jwt.secret, { expiresIn: '1h' });
  return { user, auth: { Authorization: `Bearer ${token}` } };
}

const purl = (eco, name, version) => `pkg:${eco === 'PyPI' ? 'pypi' : 'npm'}/${name.split('/').map(encodeURIComponent).join('/')}@${version}`;

// Shaped like scannerService output (B1's mapFinding), already saved by the worker.
const FINDINGS = [
  {
    vulnId: 'GHSA-jf85-cpcp-j695', aliases: ['CVE-2019-10744'], cveIds: ['CVE-2019-10744'],
    summary: 'Prototype Pollution in lodash', package: { name: 'lodash', version: '4.17.11', ecosystem: 'npm' },
    direct: true, severity: 'critical', score: 9.1, scoreSource: 'osv',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H',
    fixedVersions: ['4.17.12'], recommendedFix: '4.17.12', hasFix: true,
    references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-jf85-cpcp-j695' }],
  },
  {
    vulnId: 'GHSA-hrpp-h998-j3pp', aliases: ['CVE-2022-24999'], cveIds: ['CVE-2022-24999'],
    summary: 'qs vulnerable to Prototype Pollution', package: { name: 'qs', version: '6.5.2', ecosystem: 'npm' },
    severity: 'high', score: 7.5, scoreSource: 'osv', cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    fixedVersions: ['6.10.3'], recommendedFix: '6.10.3', hasFix: true,
  },
  {
    // OSV had no CVSS vector: the fallback lookup fills this one in.
    vulnId: 'GHSA-grv7-fg5c-xmjg', aliases: ['CVE-2024-4068'], cveIds: ['CVE-2024-4068'],
    summary: 'Uncontrolled resource consumption in braces', package: { name: 'braces', version: '3.0.2', ecosystem: 'npm' },
    severity: 'unknown', score: null, scoreSource: null,
    fixedVersions: ['3.0.3'], recommendedFix: '3.0.3', hasFix: true,
  },
  {
    vulnId: 'PYSEC-2023-212', aliases: ['CVE-2023-43804'], cveIds: ['CVE-2023-43804'],
    summary: 'urllib3 Cookie header not stripped on cross-origin redirects', package: { name: 'urllib3', version: '1.26.5', ecosystem: 'PyPI' },
    severity: 'medium', score: 5.9, scoreSource: 'osv', cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    fixedVersions: ['1.26.17'], recommendedFix: '1.26.17', hasFix: true,
  },
];

const COMPONENTS = [
  ['@babel/core', '7.22.0', 'npm', true, ['MIT']],
  ['braces', '3.0.2', 'npm', false, ['MIT']],
  ['express', '4.17.1', 'npm', true, ['MIT']],
  ['lodash', '4.17.11', 'npm', true, ['MIT']],
  ['qs', '6.5.2', 'npm', false, ['BSD-3-Clause']],
  ['requests', '2.25.1', 'PyPI', true, ['Apache-2.0']],
  ['urllib3', '1.26.5', 'PyPI', false, ['MIT']],
];

/** A user's repo with one completed scan, its findings and components. */
async function seedRepo(owner, { name = 'acme/shop-api' } = {}) {
  const repo = await Repo.create({ owner: owner._id, url: `https://github.com/${name}`, name });
  const scan = await Scan.create({
    repo: repo._id, status: 'completed', commitSha: 'a1b2c3d4e5f6', startedAt: new Date(), finishedAt: new Date(),
  });
  repo.lastScan = scan._id;
  await repo.save();
  const findings = await Finding.insertMany(FINDINGS.map((f) => ({
    ...f,
    package: { ...f.package, purl: purl(f.package.ecosystem, f.package.name, f.package.version) },
    repo: repo._id,
    scan: scan._id,
  })));
  const sev = new Map(FINDINGS.map((f) => [`${f.package.name}@${f.package.version}`, f.severity]));
  const components = await Component.insertMany(COMPONENTS.map(([n, v, eco, direct, licenses]) => ({
    repo: repo._id, scan: scan._id, name: n, version: v, ecosystem: eco, direct, licenses,
    purl: purl(eco, n, v),
    vulnerabilityCount: sev.has(`${n}@${v}`) ? 1 : 0,
    maxSeverity: sev.get(`${n}@${v}`) || null,
  })));
  return { repo, scan, findings, components };
}

/** Fake cvelistV5 lookup: answers from a map and records the ids asked for. */
function stubCveLookup(records = {}) {
  const calls = [];
  return {
    calls,
    async lookup(id) {
      calls.push(id);
      const r = records[id];
      if (r instanceof Error) throw r;
      return r || null;
    },
  };
}

module.exports = { useDatabase, makeUser, seedRepo, stubCveLookup, FINDINGS, COMPONENTS };
