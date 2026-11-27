// jest.config.js – project-wide Jest configuration
module.exports = {
  // Starts an in-memory MongoDB for every test file (tests/setup.js)
  setupFilesAfterEnv: ['./tests/setup.js'],
  // Starting MongoDB and full scan tests can exceed Jest's 5s default
  testTimeout: 30000,
  // Run all tests under /tests/
  testMatch: ['**/tests/**/*.test.js'],
  // Keep the generated CycloneDX schema out of coverage reports
  coveragePathIgnorePatterns: ['/node_modules/', '/src/services/cyclonedx/schema/'],
};
