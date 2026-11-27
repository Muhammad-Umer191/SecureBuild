// jest.config.js – project-wide Jest configuration
module.exports = {
  testEnvironment:        'node',
  testTimeout:            30000,
  setupFilesAfterEnv:     ['./tests/setup.js'],
  // Run all tests under /tests/
  testMatch:              ['**/tests/**/*Test.js', '**/tests/**/*.test.js'],
  // Don't collect coverage from generated schemas or service internals by default
  coveragePathIgnorePatterns: ['/node_modules/', '/src/services/cyclonedx/schema/'],
  // Tell mongodb-memory-server to use the system-installed mongod binary
  // instead of trying to download one (sandbox has no network).
  globalSetup: undefined,
  testEnvironmentOptions: {},
};
