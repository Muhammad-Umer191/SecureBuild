// Centralised config – reads .env once and exports typed values.
require('dotenv').config();

module.exports = {
  port: parseInt(process.env.PORT, 10) || 4000,
  nodeEnv: process.env.NODE_ENV || 'development',

  mongo: {
    uri: process.env.MONGO_URI || 'mongodb://localhost:27017/securebuild',
  },

  jwt: {
    secret: process.env.JWT_SECRET || 'dev-secret-do-not-use-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  },

  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },

  scanner: {
    cloneTimeoutMs: parseInt(process.env.CLONE_TIMEOUT_MS, 10) || 60_000,
    cloneMaxDepth: parseInt(process.env.CLONE_MAX_DEPTH, 10) || 1,
    repoMaxSizeMb: parseInt(process.env.REPO_MAX_SIZE_MB, 10) || 200,
  },

  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  },
};
