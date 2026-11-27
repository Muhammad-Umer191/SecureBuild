// tests/setup.js – runs before every test file (jest.config.js: setupFilesAfterEnv)
// Spins up an in-memory MongoDB so tests never touch your real database.
//
// In sandbox / CI environments that have no network, point mongodb-memory-server
// at the system-installed mongod binary so it never tries to download one.
// Only when that binary exists: on Windows/macOS (or Linux without mongod) the
// package downloads MongoDB once instead, so the tests run on every machine.
const fs = require('fs');

const SYSTEM_MONGOD = '/usr/bin/mongod';
if (!process.env.MONGOMS_SYSTEM_BINARY && fs.existsSync(SYSTEM_MONGOD)) {
  process.env.MONGOMS_SYSTEM_BINARY = SYSTEM_MONGOD;
  process.env.MONGOMS_VERSION = process.env.MONGOMS_VERSION || '8.3.9';
  process.env.MONGOMS_SKIP_MD5_CHECK = '1';
}
process.env.MONGOMS_PREFER_GLOBAL_PATH = '1';

const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

let mongod;

// The first run on a new machine downloads MongoDB (~600 MB), so allow it time.
const FIRST_START_TIMEOUT_MS = 10 * 60 * 1000;

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
}, FIRST_START_TIMEOUT_MS);

afterAll(async () => {
  await mongoose.disconnect();
  if (mongod) await mongod.stop();
});

afterEach(async () => {
  // Clean every collection after each test so tests are fully isolated.
  for (const col of Object.values(mongoose.connection.collections)) {
    await col.deleteMany({});
  }
});
