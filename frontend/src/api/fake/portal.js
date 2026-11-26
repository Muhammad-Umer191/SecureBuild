// Fake API implementations for Auth, Repositories, and Scan History.
// Used when VITE_USE_FAKE_API=true so F1's UI works before backend routes are pushed.
import { ApiError, getToken } from '../client.js';
import { validateRepoUrl } from '../repos.js';
import { SCAN } from './data.js';

const LATENCY = 200;
const clone = (v) => JSON.parse(JSON.stringify(v));
const wait = (v) => new Promise((resolve) => setTimeout(() => resolve(v), LATENCY));
const failLater = (status, code, message) =>
  new Promise((_, reject) => setTimeout(() => reject(new ApiError(message, { code, status })), LATENCY));

// Pre-seeded demo users covering every role supported by FindingDetailDrawer.
const SEED_USERS = [
  { id: '665000000000000000000a01', name: 'Ahsan (Admin)', email: 'admin@securebuild.dev', password: 'password123', role: 'admin' },
  { id: '665000000000000000000a02', name: 'Umer (Analyst)', email: 'analyst@securebuild.dev', password: 'password123', role: 'analyst' },
  { id: '665000000000000000000a03', name: 'Guest (Viewer)', email: 'viewer@securebuild.dev', password: 'password123', role: 'viewer' },
];

const SEED_REPOS = [
  {
    id: '6650a1b2c3d4e5f600000000',
    name: 'acme/demo-repo',
    url: 'https://github.com/acme/demo-repo',
    status: 'idle',
    lastScan: { ...SCAN, status: 'completed', findingsCount: 12, componentsCount: 40 },
    createdAt: '2026-11-01T09:00:00.000Z',
  },
  {
    id: '6650a1b2c3d4e5f600000010',
    name: 'acme/payment-service',
    url: 'https://github.com/acme/payment-service',
    status: 'idle',
    lastScan: {
      id: '6650a1b2c3d4e5f600000011',
      status: 'completed',
      commitSha: '9f8e7d6',
      startedAt: '2026-11-09T14:00:00.000Z',
      finishedAt: '2026-11-09T14:01:12.000Z',
      findingsCount: 4,
      componentsCount: 18,
    },
    createdAt: '2026-11-03T11:30:00.000Z',
  },
];

const SEED_SCANS = {
  '6650a1b2c3d4e5f600000000': [
    {
      id: SCAN.id,
      repo: '6650a1b2c3d4e5f600000000',
      status: 'completed',
      commitSha: SCAN.commitSha,
      startedAt: '2026-11-10T09:11:10.000Z',
      finishedAt: SCAN.finishedAt,
      error: null,
      findingsCount: 12,
      componentsCount: 40,
    },
    {
      id: '6650a1b2c3d4e5f600000002',
      repo: '6650a1b2c3d4e5f600000000',
      status: 'failed',
      commitSha: '77c10e2',
      startedAt: '2026-11-08T16:20:00.000Z',
      finishedAt: '2026-11-08T16:20:08.000Z',
      error: 'Lockfile missing or unreadable during archive extraction.',
      findingsCount: 0,
      componentsCount: 0,
    },
  ],
  '6650a1b2c3d4e5f600000010': [
    {
      id: '6650a1b2c3d4e5f600000011',
      repo: '6650a1b2c3d4e5f600000010',
      status: 'completed',
      commitSha: '9f8e7d6',
      startedAt: '2026-11-09T14:00:00.000Z',
      finishedAt: '2026-11-09T14:01:12.000Z',
      error: null,
      findingsCount: 4,
      componentsCount: 18,
    },
  ],
};

let users = clone(SEED_USERS);
let repos = clone(SEED_REPOS);
let scansByRepo = clone(SEED_SCANS);
let nextCounter = 20;

/** Reset in-memory mock data (used by unit tests). */
export function resetFakePortalState() {
  users = clone(SEED_USERS);
  repos = clone(SEED_REPOS);
  scansByRepo = clone(SEED_SCANS);
  nextCounter = 20;
}

function publicUser(user) {
  const { id, name, email, role } = user;
  return { id, name, email, role };
}

function makeFakeToken(userId) {
  return `fake-token:${userId}`;
}

export async function login({ email, password }) {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  if (!normalizedEmail || !password) {
    return failLater(400, 'VALIDATION_ERROR', 'Email and password are required.');
  }

  const found = users.find((u) => u.email.toLowerCase() === normalizedEmail);
  if (!found || found.password !== password) {
    return failLater(401, 'INVALID_CREDENTIALS', 'Invalid email or password.');
  }

  return wait({ token: makeFakeToken(found.id), user: publicUser(found) });
}

export async function register({ name, email, password }) {
  const cleanName = String(name || '').trim();
  const normalizedEmail = String(email || '').trim().toLowerCase();

  if (!cleanName) return failLater(400, 'VALIDATION_ERROR', 'Name is required.');
  if (!/^\S+@\S+\.\S+$/.test(normalizedEmail)) {
    return failLater(400, 'VALIDATION_ERROR', 'Please enter a valid email address.');
  }
  if (!password || password.length < 8) {
    return failLater(400, 'VALIDATION_ERROR', 'Password must be at least 8 characters.');
  }
  if (users.some((u) => u.email.toLowerCase() === normalizedEmail)) {
    return failLater(409, 'EMAIL_EXISTS', 'An account with this email already exists.');
  }

  nextCounter += 1;
  const created = {
    id: `665000000000000000000a${nextCounter}`,
    name: cleanName,
    email: normalizedEmail,
    password,
    role: 'analyst',
  };
  users.push(created);

  return wait({ token: makeFakeToken(created.id), user: publicUser(created) });
}

export async function getMe() {
  const token = getToken();
  if (!token || !token.startsWith('fake-token:')) {
    return failLater(401, 'AUTH_INVALID', 'Session expired. Please sign in again.');
  }

  const userId = token.slice('fake-token:'.length);
  const found = users.find((u) => u.id === userId);
  if (!found) {
    return failLater(401, 'AUTH_INVALID', 'User no longer exists.');
  }

  return wait(publicUser(found));
}

export async function listRepos() {
  return wait({ items: clone(repos) });
}

export async function addRepo({ url }) {
  const check = validateRepoUrl(url);
  if (!check.valid) {
    return failLater(400, 'VALIDATION_ERROR', check.error);
  }
  if (repos.some((r) => r.url.toLowerCase() === check.normalizedUrl.toLowerCase())) {
    return failLater(409, 'DUPLICATE_REPO', 'This repository has already been added.');
  }

  nextCounter += 1;
  const id = `6650a1b2c3d4e5f6000000${nextCounter}`;
  const now = new Date().toISOString();
  const initialScan = {
    id: `6650a1b2c3d4e5f6000001${nextCounter}`,
    repo: id,
    status: 'completed',
    commitSha: 'c4d5e6f',
    startedAt: now,
    finishedAt: now,
    error: null,
    findingsCount: 12,
    componentsCount: 40,
  };

  const repo = {
    id,
    name: check.name,
    url: check.normalizedUrl,
    status: 'idle',
    lastScan: initialScan,
    createdAt: now,
  };

  repos.unshift(repo);
  scansByRepo[id] = [initialScan];

  return wait(clone(repo));
}

export async function deleteRepo(repoId) {
  const idx = repos.findIndex((r) => r.id === repoId);
  if (idx === -1) {
    return failLater(404, 'NOT_FOUND', 'Repository not found.');
  }

  repos.splice(idx, 1);
  delete scansByRepo[repoId];
  return wait({ deleted: true, id: repoId });
}

export async function triggerScan(repoId) {
  const repo = repos.find((r) => r.id === repoId);
  if (!repo) {
    return failLater(404, 'NOT_FOUND', 'Repository not found.');
  }

  nextCounter += 1;
  const now = new Date().toISOString();
  const newScan = {
    id: `6650a1b2c3d4e5f6000002${nextCounter}`,
    repo: repoId,
    status: 'completed',
    commitSha: `f${nextCounter}a9b1`,
    startedAt: now,
    finishedAt: now,
    error: null,
    findingsCount: 12,
    componentsCount: 40,
  };

  scansByRepo[repoId] = [newScan, ...(scansByRepo[repoId] || [])];
  repo.lastScan = newScan;
  repo.status = 'idle';

  return wait(clone(newScan));
}

export async function listScans(repoId) {
  if (!repos.some((r) => r.id === repoId)) {
    return failLater(404, 'NOT_FOUND', 'Repository not found.');
  }
  return wait({ items: clone(scansByRepo[repoId] || []) });
}
