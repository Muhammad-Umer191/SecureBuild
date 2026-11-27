// tests/setup.js – runs before every test file (jest.config.js: setupFilesAfterEnv)
// Spins up an in-memory MongoDB so tests never touch your real database.
//
// In sandbox / CI environments that have no network, point mongodb-memory-server
// at the system-installed mongod binary so it never tries to download one.
process.env.MONGOMS_SYSTEM_BINARY = process.env.MONGOMS_SYSTEM_BINARY || '/usr/bin/mongod';
process.env.MONGOMS_VERSION = process.env.MONGOMS_VERSION || '8.3.9';
process.env.MONGOMS_PREFER_GLOBAL_PATH = '1';
process.env.MONGOMS_SKIP_MD5_CHECK = '1';

const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

let mongod;

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
});

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
